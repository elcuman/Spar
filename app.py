from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'b2b-super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///b2b_database.db'
db = SQLAlchemy(app)

# --- LOGIN YONETIMI ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- VERITABANI MODELLERI ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    company_name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(10), nullable=False) # 'Alım' veya 'Satım'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref='posts')

# --- ROTALAR (ROUTES) ---

@app.route('/')
def index():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=request.form['username'], 
                        company_name=request.form['company_name'], 
                        password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Başarıyla kayıt oldunuz! Giriş yapabilirsiniz.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Kullanıcı adı veya şifre hatalı!')
    return render_template('login.html')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        new_post = Post(title=request.form['title'], 
                        content=request.form['content'], 
                        type=request.form['type'], 
                        author=current_user)
        db.session.add(new_post)
        db.session.commit()
        flash('İlanınız başarıyla yayınlandı.')
        return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- ADMIN ROTALARI ---
@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash("Bu sayfaya sadece yöneticiler girebilir!")
        return redirect(url_for('index'))
    users = User.query.all()
    posts = Post.query.all()
    return render_template('admin.html', users=users, posts=posts)

@app.route('/admin/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    if not current_user.is_admin: return "Yetkisiz", 403
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)