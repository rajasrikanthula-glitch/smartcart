from flask import Flask, render_template, request, redirect, session, flash,url_for,make_response
from flask_mail import Mail, Message
import sqlite3
import os
import bcrypt
import random
import config
import time
import re
import razorpay
from utils.pdf_generator import generate_pdf

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)
# ---------------- DB CONNECTION (SQLite) --------------
# The whole database is ONE file: smartcart.db (created automatically)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))     # full path of the project folder
DB_PATH = os.path.join(BASE_DIR, 'smartcart.db')

# bcrypt gives bytes; store them as normal text in SQLite
sqlite3.register_adapter(bytes, lambda b: b.decode('utf-8'))


def dict_factory(cursor, row):
    """Return every row as a dictionary, like MySQL's dictionary=True"""
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


class SQLiteConnection(sqlite3.Connection):
    def cursor(self, dictionary=False, **kwargs):
        # accepts dictionary=True so the old code keeps working
        return super().cursor()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, factory=SQLiteConnection)
    conn.row_factory = dict_factory
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def password_to_bytes(value):
    """Handle bcrypt hashes stored as either TEXT or BLOB in SQLite."""
    if isinstance(value, bytes):
        return value
    return str(value).encode('utf-8')


def init_db():
    """Create all tables if they do not exist yet"""
    conn = get_db_connection()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS admin (
        admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        profile_image TEXT
    );

    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        profile_image TEXT
    );

    CREATE TABLE IF NOT EXISTS products (
        product_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        category TEXT,
        price REAL NOT NULL,
        image TEXT,
        admin_id INTEGER,
        FOREIGN KEY (admin_id) REFERENCES admin(admin_id)
    );

    CREATE TABLE IF NOT EXISTS orders (
        order_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        razorpay_order_id TEXT,
        razorpay_payment_id TEXT UNIQUE,
        amount REAL,
        payment_status TEXT,
        name TEXT,
        email TEXT,
        phone TEXT,
        door_no TEXT,
        address TEXT,
        city TEXT,
        pincode TEXT,
        created_at TEXT DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        product_name TEXT,
        quantity INTEGER,
        price REAL,
        FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(product_id)
    );
    """)
    conn.commit()
    conn.close()


init_db()
# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    # Show form
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    # POST → Process signup
    name = request.form['name']
    email = request.form['email'].strip().lower()

    # 1️⃣ Check if admin email already exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    # 2️⃣ Save user input temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # 3️⃣ Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # 4️⃣ Send OTP Email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    try:
        mail.send(message)
    except Exception as e:
        print("Email error:", e)
        flash("Could not send the OTP email right now. Please try again later.", "danger")
        return redirect('/admin-signup')

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')



# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")



# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-signup')
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Show login page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # POST → Validate login
    email = request.form['email']
    password = request.form['password']

    # Step 1: Check if admin email exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # Step 2: Compare entered password with hashed password
    stored_hashed_password = password_to_bytes(admin['password'])

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    # Step 5: If login success → Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')



# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])



# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')
import os
from werkzeug.utils import secure_filename

# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads', 'product_images')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")



# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    # 2️⃣ Validate image upload
    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    # 3️⃣ Secure the file name
    filename = secure_filename(image_file.filename)

    # 4️⃣ Create full path
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # 5️⃣ Save image into folder
    image_file.save(image_path)

    # 6️⃣ Insert product into database
    conn = get_db_connection()
    cursor = conn.cursor()
    admin_id = session['admin_id']
    cursor.execute(
        """INSERT INTO products
    (name, description, category, price, image, admin_id)
    VALUES (?, ?, ?, ?, ?, ?)""",
    (name, description, category, price, filename, admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')
# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
# ROUTE 13:UPDATED PRODUCT LIST WITH SEARCH + CATEGORY FILTER
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch category list for dropdown
    admin_id = session['admin_id']

    cursor.execute(
    "SELECT DISTINCT category FROM products WHERE admin_id = ?",
    (admin_id,))
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = "SELECT * FROM products WHERE admin_id = ?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )


# =================================================================
#  route-13 DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch product to get image name
    cursor.execute(
        "SELECT image FROM products WHERE product_id=? AND admin_id=?",
        (item_id, session['admin_id']))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # 2️⃣ Delete product from DB first
    try:
        cursor.execute(
            "DELETE FROM products WHERE product_id=? AND admin_id=?",
            (item_id, session['admin_id']))
        conn.commit()
    except sqlite3.IntegrityError:
        # product is used in customer orders
        conn.rollback()
        cursor.close()
        conn.close()
        flash("This product is part of customer orders, so it cannot be deleted.", "danger")
        return redirect('/admin/item-list')

    # 3️⃣ Delete image only if no other product uses the same file
    cursor.execute("SELECT COUNT(*) AS c FROM products WHERE image=?", (image_name,))
    still_used = cursor.fetchone()['c']
    cursor.close()
    conn.close()

    if image_name and not still_used:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
        if os.path.exists(image_path):
            os.remove(image_path)

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ROUTE: DELETE ALL PRODUCTS
# =================================================================
@app.route('/admin/delete-all-items')
def delete_all_items():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check products belonging to this admin
        cursor.execute("SELECT product_id, image FROM products WHERE admin_id=?", (admin_id,))
        products_to_delete = cursor.fetchall()

        # If none with this specific admin_id, allow cleaning up all products
        if not products_to_delete:
            cursor.execute("SELECT product_id, image FROM products")
            products_to_delete = cursor.fetchall()

        if not products_to_delete:
            flash("No products found to delete.", "info")
            return redirect('/admin/item-list')

        prod_ids = [p['product_id'] for p in products_to_delete]
        placeholders = ','.join('?' for _ in prod_ids)

        # Remove referencing order items first to satisfy foreign keys
        cursor.execute(f"DELETE FROM order_items WHERE product_id IN ({placeholders})", prod_ids)

        # Delete the products
        cursor.execute(f"DELETE FROM products WHERE product_id IN ({placeholders})", prod_ids)
        conn.commit()

        # Clean up images if no longer used
        for p in products_to_delete:
            image_name = p.get('image')
            if image_name:
                cursor.execute("SELECT COUNT(*) AS c FROM products WHERE image=?", (image_name,))
                still_used = cursor.fetchone()['c']
                if not still_used:
                    image_path = os.path.join(app.config.get('UPLOAD_FOLDER', 'static/uploads/product_images'), image_name)
                    if os.path.exists(image_path):
                        try:
                            os.remove(image_path)
                        except Exception:
                            pass

        flash(f"Successfully deleted {len(products_to_delete)} products!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting products: {e}", "danger")
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass

    return redirect('/admin/item-list')


#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
    "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
    (item_id, session['admin_id']))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)

# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
    "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
    (item_id, session['admin_id']))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)

#🟩 Step 2: Update Product Logic
#Route: /admin/update-item/<id> (POST)
# =================================================================
# ROUTE-12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
    "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
    (item_id, session['admin_id']))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        
        # Secure filename
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database
    cursor.execute("""
    UPDATE products
    SET name=?, description=?, category=?, price=?, image=?
    WHERE product_id=? AND admin_id=?
""", (name, description, category, price, final_image_name, item_id, session['admin_id']))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')
ADMIN_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads', 'admin_profiles')
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER
os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)


# =================================================================
# ROUTE 1: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)
# =================================================================
# ROUTE 2: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')

# =================================================================
# FORGOT PASSWORD - SEND OTP
# =================================================================
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'GET':
        return render_template("admin/forgot_password.html")

    # Normalize the entered email so uppercase letters or accidental spaces
    # do not prevent an existing admin from being found.
    email = request.form.get('email', '').strip().lower()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE lower(trim(email))=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if not admin:
        flash("If the email is registered, an OTP will be sent.", "info")
        return redirect('/forgot-password')

    otp = random.randint(100000, 999999)

    session['reset_email'] = admin['email']
    session['reset_otp'] = otp
    session['reset_otp_expiry'] = time.time() + 300
    session.pop('reset_verified', None)

    message = Message(
        subject="SmartCart Password Reset OTP",
        sender=config.MAIL_USERNAME,
        recipients=[admin['email']]
    )

    message.body = f"Your password reset OTP is: {otp}. It is valid for 5 minutes."

    try:
        mail.send(message)
    except Exception as e:
        print("Email error:", e)
        flash("Could not send the OTP email right now. Please try again later.", "danger")
        return redirect('/forgot-password')

    flash("OTP sent to your registered email!", "success")
    return redirect('/verify-reset-otp')


# =================================================================
# VERIFY RESET OTP
# =================================================================
@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():

    if 'reset_email' not in session:
        return redirect('/forgot-password')

    if request.method == 'GET':
        return render_template("admin/verify_reset_otp.html")

    user_otp = request.form['otp']

    if time.time() > session.get('reset_otp_expiry', 0):
        session.pop('reset_otp', None)
        session.pop('reset_email', None)
        session.pop('reset_otp_expiry', None)

        flash("OTP expired! Please try again.", "danger")
        return redirect('/forgot-password')

    if str(session.get('reset_otp')) != user_otp:
        flash("Invalid OTP! Try again.", "danger")
        return redirect('/verify-reset-otp')

    session['reset_verified'] = True

    flash("OTP verified successfully!", "success")
    return redirect('/reset-password')


# =================================================================
# RESET PASSWORD
# =================================================================
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():

    if not session.get('reset_verified') or 'reset_email' not in session:
        flash("Please verify OTP first!", "danger")
        return redirect('/forgot-password')

    if request.method == 'GET':
        return render_template("admin/reset_password.html")

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect('/reset-password')

    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    )

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE admin SET password=? WHERE email=?",
        (hashed_password, session['reset_email'])
    )

    conn.commit()
    cursor.close()
    conn.close()

    session.pop('reset_email', None)
    session.pop('reset_otp', None)
    session.pop('reset_otp_expiry', None)
    session.pop('reset_verified', None)

    flash("Password reset successfully! Please login.", "success")
    return redirect('/admin-login')
# ROUTE: USER REGISTRATION
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Check if user already exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed_password)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')

#⭐ ROUTE 2: User Login (GET + POST)
# =================================================================
# ROUTE: USER LOGIN
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), password_to_bytes(user['password'])):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')

#⭐ ROUTE 3: User Dashboard (Protected)
# =================================================================
# ROUTE: USER DASHBOARD
# =================================================================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    return render_template("user/user_home.html", user_name=session['user_name'])

#⭐ ROUTE 4: User Logout
# =================================================================
# ROUTE: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')

# ROUTE: USER PRODUCT LISTING (SEARCH + FILTER)
# =================================================================
@app.route('/user/products')
def user_products():

    # Optional: restrict only logged-in users
    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Build dynamic SQL
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )

#⭐ ROUTE 2: Single Product Details Page
# =================================================================
# ROUTE: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)

# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer or '/user/products')

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")
    return redirect(request.referrer or '/user/products')   # instead of this line use below line
    
#⭐ ROUTE 2: View Cart Page
# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)

##⭐ ROUTE 3: Increase Quantity
# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')

#⭐ ROUTE 4: Decrease Quantity
# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')

#⭐ ROUTE 5: Remove Item Completely
# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')

# =================================================================
# HELPER: GET ONLY THE TICKED PRODUCTS (FROM SESSION CART)
# =================================================================
def get_selected_items():
    cart = session.get('cart', {})
    selected_pids = session.get('selected_pids', [])

    items = []
    total = 0

    for pid in selected_pids:
        item = cart.get(pid)
        if not item:
            continue
        line_total = round(item['price'] * item['quantity'], 2)
        items.append({
            'pid': pid,
            'name': item['name'],
            'price': item['price'],
            'quantity': item['quantity'],
            'total': line_total
        })
        total += line_total

    return items, round(total, 2)


# =================================================================
# ROUTE: PROCEED FROM CART  (only ticked products come here)
# =================================================================
@app.route('/user/checkout', methods=['GET', 'POST'])
def checkout():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    if request.method == 'POST':
        cart = session.get('cart', {})
        selected = [pid for pid in request.form.getlist('selected_products') if pid in cart]

        if not selected:
            flash("Please tick at least one product!", "danger")
            return redirect('/user/cart')

        session['selected_pids'] = selected

    items, total = get_selected_items()

    if not items:
        flash("Please select products first!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/checkout.html",
        selected_items=items,
        selected_total=total,
        saved=session.get('delivery', {})
    )


# =================================================================
# ROUTE: SAVE DELIVERY DETAILS  → go to payment
# =================================================================
@app.route('/user/checkout/details', methods=['POST'])
def checkout_details():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    items, total = get_selected_items()
    if not items:
        flash("Please select products first!", "danger")
        return redirect('/user/cart')

    fields = ['name', 'email', 'phone', 'door_no', 'address', 'city', 'pincode']
    delivery = {f: request.form.get(f, '').strip() for f in fields}

    if not all(delivery.values()):
        flash("Please fill all the details!", "danger")
        return redirect('/user/checkout')

    if not re.fullmatch(r'\d{6}', delivery['pincode']):
        flash("Pincode must be 6 digits!", "danger")
        return redirect('/user/checkout')

    if not re.fullmatch(r'[6-9]\d{9}', delivery['phone']):
        flash("Enter a valid 10-digit mobile number!", "danger")
        return redirect('/user/checkout')

    session['delivery'] = delivery
    return redirect('/user/pay')


# =================================================================
# ROUTE: CREATE RAZORPAY ORDER + SHOW PAYMENT PAGE
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    items, total = get_selected_items()
    if not items:
        flash("Please select products first!", "danger")
        return redirect('/user/cart')

    delivery = session.get('delivery')
    if not delivery:
        return redirect('/user/checkout')

    amount_paise = int(round(total * 100))   # Razorpay needs paise

    try:
        razorpay_order = razorpay_client.order.create({
            "amount": amount_paise,
            "currency": "INR",
            "payment_capture": 1
        })
    except Exception as e:
        print("Razorpay error:", e)
        flash("Could not start payment. Please try again.", "danger")
        return redirect('/user/checkout')

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        items=items,
        total=total,
        delivery=delivery,
        amount_paise=amount_paise,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


# =================================================================
# ROUTE: VERIFY PAYMENT + STORE ORDER (DAY 13)
# =================================================================
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature) \
            or razorpay_order_id != session.get('razorpay_order_id'):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # 1) Make sure the payment really came from Razorpay
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        })
    except Exception as e:
        print("Razorpay verification failed:", e)
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # 2) Only the ticked products + delivery details
    items, total_amount = get_selected_items()
    delivery = session.get('delivery')

    if not items or not delivery:
        flash("Order details missing. Cannot create order.", "danger")
        return redirect('/user/cart')

    # 3) Store order + order items
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO orders
            (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status,
             name, email, phone, door_no, address, city, pincode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session['user_id'], razorpay_order_id, razorpay_payment_id, total_amount, 'paid',
              delivery['name'], delivery['email'], delivery['phone'], delivery['door_no'],
              delivery['address'], delivery['city'], delivery['pincode']))

        order_db_id = cursor.lastrowid

        for item in items:
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (order_db_id, int(item['pid']), item['name'], item['quantity'], item['price']))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Order storage failed:", e)
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()

    # 4) Remove only the paid products from the cart
    cart = session.get('cart', {})
    for item in items:
        cart.pop(item['pid'], None)
    session['cart'] = cart

    session.pop('selected_pids', None)
    session.pop('delivery', None)
    session.pop('razorpay_order_id', None)

    flash("Payment successful and order placed!", "success")
    return redirect(f"/user/order-success/{order_db_id}")


# =================================================================
# ROUTE: ORDER SUCCESS PAGE
# =================================================================
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?",
                   (order_db_id, session['user_id']))
    order = cursor.fetchone()

    items = []
    if order:
        cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_db_id,))
        items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)


# =================================================================
# ROUTE: MY ORDERS
# =================================================================
@app.route('/user/my-orders')
def my_orders():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC",
                   (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)

# =================================================================
# CART COUNT (all templates lo use cheyochu)
# =================================================================
@app.context_processor
def inject_cart_count():
    cart = session.get('cart', {})
    return {'cart_count': sum(item['quantity'] for item in cart.values())}

# =================================================================
# ROUTE: DOWNLOAD INVOICE (PDF)  - DAY 14
# =================================================================
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    items = []
    if order:
        cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_id,))
        items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response
# =================================================================
# ROUTE: VIEW INVOICE (HTML page, no PDF library)
# =================================================================
@app.route("/user/invoice/<int:order_id>")
def view_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    items = []
    if order:
        cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_id,))
        items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    return render_template("user/invoice.html", order=order, items=items)
# =================================================================
# ROUTE: HOME PAGE
# =================================================================
@app.route('/')
def home():
    return render_template("index.html")

# =================================================================
# USER PROFILE (VIEW + UPDATE NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
USER_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads', 'user_profiles')
app.config['USER_UPLOAD_FOLDER'] = USER_UPLOAD_FOLDER
os.makedirs(USER_UPLOAD_FOLDER, exist_ok=True)


@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
    user = cursor.fetchone()

    # ---------------- UPDATE PROFILE ----------------
    if request.method == 'POST':

        name = request.form['name'].strip()
        email = request.form['email'].strip()
        new_password = request.form.get('password', '')
        new_image = request.files.get('profile_image')

        # Email must not belong to another user
        cursor.execute("SELECT user_id FROM users WHERE email=? AND user_id<>?",
                       (email, user_id))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            flash("This email is already used by another account!", "danger")
            return redirect('/user/profile')

        # Change password only if a new one is typed
        if new_password:
            password_to_save = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        else:
            password_to_save = user['password']

        # Save new image only if a file is chosen
        image_name = user.get('profile_image')

        if new_image and new_image.filename != "":
            ext = os.path.splitext(new_image.filename)[1].lower()

            if ext not in ('.jpg', '.jpeg', '.png', '.gif', '.webp'):
                cursor.close()
                conn.close()
                flash("Only JPG, PNG, GIF or WEBP images are allowed!", "danger")
                return redirect('/user/profile')

            # unique name per user, so one user can never overwrite another's image
            new_filename = f"user_{user_id}_{int(time.time())}{ext}"
            new_image.save(os.path.join(app.config['USER_UPLOAD_FOLDER'], new_filename))

            # delete the old image
            if image_name:
                old_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], image_name)
                if os.path.exists(old_path):
                    os.remove(old_path)

            image_name = new_filename

        cursor.execute("""
            UPDATE users
            SET name=?, email=?, password=?, profile_image=?
            WHERE user_id=?
        """, (name, email, password_to_save, image_name, user_id))
        conn.commit()

        cursor.close()
        conn.close()

        session['user_name'] = name
        session['user_email'] = email

        flash("Profile updated successfully!", "success")
        return redirect('/user/profile')

    # ---------------- SHOW PROFILE ----------------
    cursor.close()
    conn.close()

    return render_template("user/user_profile.html", user=user)
# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)