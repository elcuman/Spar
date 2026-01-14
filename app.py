from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'b2b-global-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///b2b_v4.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- MODELLER ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    company_name = db.Column(db.String(120), nullable=False)
    sector = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(10), nullable=False) # 'Alım' veya 'Satım'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref='posts')

class Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    price_offer = db.Column(db.String(50))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post = db.relationship('Post', backref=db.backref('offers', cascade="all,delete", lazy=True))
    sender = db.relationship('User', backref=db.backref('my_sent_offers', lazy=True))

# --- ROTALAR ---
@app.route('/')
def index():
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    sectors = ["Teknoloji", "Gıda", "İnşaat", "Tekstil", "Lojistik", "Enerji", "Kimya", "Diğer"]
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=request.form['username'], company_name=request.form['company_name'],
                        sector=request.form['sector'], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Kayıt Başarılı! Giriş Yapabilirsiniz.')
        return redirect(url_for('login'))
    return render_template('register.html', sectors=sectors)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Hatalı bilgiler!')
    return render_template('login.html')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        new_post = Post(title=request.form['title'], content=request.form['content'], 
                        type=request.form['type'], author=current_user)
        db.session.add(new_post)
        db.session.commit()
        flash('İlanınız yayına alındı.')
        return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/send_offer/<int:post_id>', methods=['POST'])
@login_required
def send_offer(post_id):
    new_offer = Offer(message=request.form['message'], price_offer=request.form['price_offer'],
                      post_id=post_id, sender_id=current_user.id)
    db.session.add(new_offer)
    db.session.commit()
    flash('Teklifiniz firma sahibine iletildi.')
    return redirect(url_for('my_offers'))

@app.route('/my_offers')
@login_required
def my_offers():
    sent = Offer.query.filter_by(sender_id=current_user.id).all()
    my_post_ids = [p.id for p in current_user.posts]
    received = Offer.query.filter(Offer.post_id.in_(my_post_ids)).all() if my_post_ids else []
    return render_template('my_offers.html', sent=sent, received=received)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin: return redirect(url_for('index'))
    return render_template('admin.html', users=User.query.all(), posts=Post.query.all())

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', company_name='Global Admin', sector='Sistem',
                         password=generate_password_hash('admin123', method='pbkdf2:sha256'), is_admin=True)
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
