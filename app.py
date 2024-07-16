from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import logging
from functools import wraps
from flask import redirect, url_for, session, request, flash
import scrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set your secret key here

# Set of allowed extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'

mail = Mail(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# db = mysql.connector.connect(
#     host="localhost",
#     user="root",
#     password="",
#     database="justclicq"
# )
db = mysql.connector.connect(
    host="database-1.czwmgw6wkmqr.eu-north-1.rds.amazonaws.com",
    user="admin",
    password="Mberebete1234",
    database="ikazebooking",
    port=3306
)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Store the requested URL to redirect back after login
            session['next'] = request.url
            flash("Please log in to access this page.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        print(f"Received signup data: full_name={full_name}, email={email}, username={username}")

        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM Users WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()
        if existing_user:
            print("Username or email already exists.")
            flash('Username or email already exists.')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)
        try:
            cursor.execute("""
                    INSERT INTO Users (full_name, email, username, password_hash, role)
                    VALUES (%s, %s, %s, %s, %s)
                """, (full_name, email, username, password_hash, 'user'))
            db.commit()
            print("User successfully created.")
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            db.rollback()
            print(f"Error: {err}")
            flash(f"Error: {err}")
            return redirect(url_for('signup'))
        finally:
            cursor.close()

    return render_template('signup.html')


@app.route('/login/google')
def google_login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    user_email = user_info['email']

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM Users WHERE email = %s", (user_email,))
    user = cursor.fetchone()

    if user:
        session['user_id'] = user['id']
        session['role'] = user['role']

        # Redirect to the originally requested URL if available
        next_url = session.pop('next', None)
        if next_url:
            return redirect(next_url)

        if user['role'] == 'super':
            return redirect(url_for('super_admin'))
        elif user['role'] == 'admin':
            return redirect(url_for('admin_page'))
        elif user['role'] == 'host':
            return redirect(url_for('add_listing'))
        else:
            return redirect(url_for('home'))
    else:
        flash("No account associated with this Google account.")
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                # Retrieve the hashed password from the database
                hashed_password_from_db = user['password_hash']

                # Verify the password using check_password_hash
                if check_password_hash(hashed_password_from_db, password):
                    session['user_id'] = user['id']
                    session['role'] = user['role']

                    # Redirect based on user role
                    if user['role'] == 'super':
                        return redirect(url_for('super_admin'))
                    elif user['role'] == 'admin':
                        return redirect(url_for('admin_page'))
                    elif user['role'] == 'host':
                        return redirect(url_for('add_listing'))
                    else:
                        return redirect(url_for('home'))
                else:
                    flash("Invalid username or password")
            else:
                flash("Invalid username or password")
        except mysql.connector.Error as err:
            flash(f"Database error: {err}")
        finally:
            cursor.close()

    return render_template('login.html')



@app.route('/super_admin')
def super_admin():
    if 'user_id' not in session or session.get('role') != 'super':
        flash("You are not authorized to access this page")
        return redirect(url_for('login'))

    cursor = db.cursor(dictionary=True)
    try:
        # Fetch all bookings with user and listing details
        cursor.execute("""
            SELECT 
                bookings.id AS booking_id,
                Users.full_name AS fullName,
                listings.title AS listing_title,
                bookings.check_in_date,
                bookings.check_out_date,
                bookings.status
            FROM bookings
            JOIN Users ON bookings.user_id = Users.id
            JOIN listings ON bookings.listing_id = listings.id
        """)
        bookings = cursor.fetchall()
    except mysql.connector.Error as err:
        flash(f"Error fetching data: {err}")
        return redirect(url_for('login'))
    finally:
        cursor.close()

    return render_template('super_admin.html', bookings=bookings)



@app.route('/admin_page')
def admin_page():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("You are not authorized to access this page")
        return redirect(url_for('login'))

    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT id, full_name, email, username, role FROM Users WHERE role NOT IN ('admin', 'super')")
        users = cursor.fetchall()
        cursor.execute("""
            SELECT 
                bookings.id AS booking_id, 
                bookings.user_id, 
                bookings.listing_id, 
                bookings.check_in_date, 
                bookings.check_out_date, 
                bookings.status, 
                listings.title AS listing_title, 
                Users.full_name AS user_name
            FROM bookings
            JOIN listings ON bookings.listing_id = listings.id
            JOIN Users ON bookings.user_id = Users.id
            WHERE bookings.status = 'approved'
        """)
        bookings = cursor.fetchall()
    except mysql.connector.Error as err:
        flash(f"Error fetching data: {err}")
        return redirect(url_for('login'))
    finally:
        cursor.close()

    return render_template('admin_page.html', users=users, bookings=bookings)

@app.route('/toggle_activation/<int:user_id>', methods=['POST'])
def toggle_activation(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("You are not authorized to access this page")
        return redirect(url_for('login'))

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT is_active FROM Users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user:
            new_status = not user['is_active']
            cursor.execute("UPDATE Users SET is_active = %s WHERE id = %s", (new_status, user_id))
            db.commit()
            flash(f"User {'activated' if new_status else 'deactivated'} successfully.")
        else:
            flash("User not found.")
    except mysql.connector.Error as err:
        flash(f"Error updating user status: {err}")
    finally:
        cursor.close()

    return redirect(url_for('admin_page'))




@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("You are not authorized to access this page")
        return redirect(url_for('login'))

    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        username = request.form['username']
        role = request.form['role']

        try:
            cursor.execute("""
                UPDATE Users
                SET full_name = %s, email = %s, username = %s, role = %s
                WHERE id = %s
            """, (full_name, email, username, role, user_id))
            db.commit()
            flash("User updated successfully")
        except mysql.connector.Error as err:
            flash(f"Error updating user: {err}")
        finally:
            cursor.close()

        return redirect(url_for('admin_page'))

    try:
        cursor.execute("SELECT id, full_name, email, username, role FROM Users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
    except mysql.connector.Error as err:
        flash(f"Error fetching user data: {err}")
        return redirect(url_for('admin_page'))
    finally:
        cursor.close()

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("You are not authorized to perform this action")
        return redirect(url_for('login'))

    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM Users WHERE id = %s", (user_id,))
        db.commit()
        flash("User deleted successfully")
    except mysql.connector.Error as err:
        flash(f"Error deleting user: {err}")
    finally:
        cursor.close()

    return redirect(url_for('admin_page'))

@app.route('/user_portal')
def user_portal():
    return render_template('user.html')

# @app.route('/my_bookings')
# def my_bookings():
#     # Your logic for displaying bookings
#     return render_template('my_bookings.html')

@app.route('/my_bookings')
def my_bookings():
    if 'user_id' not in session:
        flash("You need to login first")
        return redirect(url_for('login'))

    return redirect(url_for('profile', user_id=session['user_id']))


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))


@app.route('/search_listings', methods=['GET'])
def search_listings():
    location = request.args.get('location', '')
    cursor = db.cursor(dictionary=True)
    sql = "SELECT * FROM listings WHERE location LIKE %s"
    cursor.execute(sql, ('%' + location + '%',))
    listings = cursor.fetchall()
    return render_template('listings.html', listings=listings)


@app.route('/listings')
def get_listings():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) FROM listings")
    total_listings = cursor.fetchone()['COUNT(*)']
    cursor.execute("SELECT * FROM listings LIMIT %s OFFSET %s", (per_page, (page-1)*per_page))
    listings = cursor.fetchall()
    return render_template('home.html', listings=listings, total_listings=total_listings, page=page, per_page=per_page)



# @app.route('/')
# def home():
#     if 'username' in session:
#         username = session['username']
#         cursor = db.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
#         user = cursor.fetchone()
#         cursor.close()
#
#     return redirect(url_for('get_listings'))
#     return redirect('/login')



@app.route('/')
def home():

        return redirect(url_for('get_listings'))

         # Pass 'user' to the template

         # Redirect to login if not logged in



@app.route('/add_listing', methods=['GET', 'POST'])
def add_listing():
    if request.method == 'POST':
        title = request.form['title']
        location = request.form['location']
        number_of_rooms = request.form['number_of_rooms']
        price = request.form['price']
        image = request.files['image']

        if image:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO listings (title, location, number_of_rooms, price, image_url, host_id) VALUES (%s, %s, %s, %s, %s, %s)",
                (title, location, number_of_rooms, price, image_url, session['user_id']))
            db.commit()
        return redirect(url_for('image_upload', listing_id=cursor.lastrowid))
        # return redirect(url_for('get_listings'))

    return render_template('add_listing.html')

# @app.route('/add_listing', methods=['GET', 'POST'])
# def add_listing():
#     if request.method == 'POST':
#         title = request.form['title']
#         location = request.form['location']
#         number_of_rooms = request.form['number_of_rooms']
#         price = request.form['price']
#         image = request.files['image']
#
#         if image and allowed_file(image.filename):
#             filename = secure_filename(image.filename)
#             image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#
#             cursor = db.cursor()
#             cursor.execute("""
#                 INSERT INTO Listings (title, location, number_of_rooms, price, image_url, user_id)
#                 VALUES (%s, %s, %s, %s, %s, %s)
#             """, (title, location, number_of_rooms, price, filename, session['user_id']))
#             db.commit()
#             cursor.close()
#
#             flash('Listing added successfully!', 'success')
#             # Redirect to the new image upload page
#             return redirect(url_for('image_upload', listing_id=cursor.lastrowid))
#
#         flash('Invalid file type', 'danger')
#
#     return render_template('add_listing.html')

@app.route('/image_upload/<int:listing_id>', methods=['GET', 'POST'])
def image_upload(listing_id):
    if request.method == 'POST':
        images = request.files.getlist('images')
        for image in images:
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                cursor = db.cursor()
                cursor.execute("""
                    INSERT INTO listingimage (listing_id, image_url)
                    VALUES (%s, %s)
                """, (listing_id, filename))
                db.commit()
                cursor.close()

        flash('Images uploaded successfully!', 'success')
        return redirect(url_for('view_listing_images', listing_id=listing_id))

    return render_template('image.html', listing_id=listing_id)

@app.route('/view_listing_images/<int:listing_id>')
def view_listing_images(listing_id):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM listingimage WHERE listing_id = %s", (listing_id,))
    images = cursor.fetchall()
    cursor.close()
    return render_template('view_images.html', images=images)






# @app.route('/listing/<int:listing_id>')
# def listing_details(listing_id):
#     cursor = db.cursor(dictionary=True)
#     cursor.execute("SELECT * FROM listings WHERE id = %s", (listing_id,))
#     listing = cursor.fetchone()
#     if listing:
#         return render_template('listing_details.html', listing=listing)
#     else:
#         return "Listing not found", 404


@app.route('/listing/<int:listing_id>')
def listing_details(listing_id):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM listings WHERE id = %s", (listing_id,))
    listing = cursor.fetchone()
    if listing:
        app.logger.info(f"Listing fetched: {listing}")  # Log the listing data
        return render_template('listing_details.html', listing=listing)
    else:
        return "Listing not found", 404



@app.route('/book/<int:listing_id>')
def book_redirect(listing_id):
    return redirect(url_for('booking_page', listing_id=listing_id))


@app.route('/booking/<int:listing_id>')
@login_required
def booking_page(listing_id):

    if session.get('role') != 'user':
        flash("You are not authorized to access this page")
        return redirect(url_for('login'))

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM listings WHERE id = %s", (listing_id,))
    listing = cursor.fetchone()
    if listing:
        return render_template('booking.html', listing=listing)
    else:
        return "Listing not found", 404




@app.route('/confirm_booking/<int:listing_id>', methods=['POST'])
def confirm_booking(listing_id):
    if 'user_id' not in session:
        flash("You need to be logged in to make a booking.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        check_in_date = request.form['check_in_date']
        check_out_date = request.form['check_out_date']
        num_rooms = request.form['num_rooms']
        num_people = request.form['num_people']

        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("""
                INSERT INTO bookings (listing_id, check_in_date, check_out_date, num_rooms, num_people, user_id, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                listing_id, check_in_date, check_out_date, num_rooms, num_people, session['user_id'], 'in progress'))
            db.commit()

            return redirect(url_for('profile', user_id=session['user_id']))
        except mysql.connector.Error as err:
            db.rollback()
            flash(f"Error: {err}")
            return redirect(url_for('booking.html', listing_id=listing_id))
        finally:
            cursor.close()

@app.route('/profile/<int:user_id>')
def profile(user_id):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_info = cursor.fetchone()

    if user_info:
        cursor.execute("SELECT * FROM bookings WHERE user_id = %s", (user_id,))
        bookings = cursor.fetchall()
        cursor.close()
        return render_template('profile.html', user_info=user_info, bookings=bookings)
    else:
        cursor.close()
        return "User not found", 404



@app.route('/update_booking_status/<int:booking_id>', methods=['POST'])
def update_booking_status(booking_id):
    if 'user_id' not in session or session.get('role') != 'host':
        flash("You are not authorized to access this page")
        return redirect(url_for('login'))

    new_status = request.form.get('status')

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            UPDATE bookings 
            SET status = %s 
            WHERE id = %s
        """, (new_status, booking_id))
        db.commit()
        flash("Booking status updated successfully!")
    except mysql.connector.Error as err:
        flash(f"Error updating booking: {err}")
    finally:
        cursor.close()

    return redirect(url_for('host_dashboard'))

def send_email_to_user(user_email, booking_id, status):
    msg = Message("Booking Status Update", recipients=[user_email])
    msg.body = f"Your booking with ID {booking_id} has been updated to {status}."
    mail.send(msg)

@app.route('/host_dashboard')
def host_dashboard():
    if 'user_id' not in session or session.get('role') != 'host':
        flash("You are not authorized to access this page")
        return redirect(url_for('login'))

    cursor = db.cursor(dictionary=True)
    try:
        # Fetch bookings for listings owned by the host
        cursor.execute("""
            SELECT 
                bookings.id AS booking_id, 
                bookings.check_in_date, 
                bookings.check_out_date, 
                bookings.status, 
                Users.full_name AS guest_name
            FROM bookings
            JOIN listings ON bookings.listing_id = listings.id
            JOIN Users ON bookings.user_id = Users.id
            WHERE listings.user_id = %s
        """, (session['user_id'],))
        bookings = cursor.fetchall()
    except mysql.connector.Error as err:
        flash(f"Error fetching data: {err}")
        return redirect(url_for('login'))
    finally:
        cursor.close()

    return render_template('host_dashboard.html', bookings=bookings)

if __name__ == '__main__':
    app.run(debug=True)
