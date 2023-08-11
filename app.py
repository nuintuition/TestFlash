from flask import Flask, jsonify, request, redirect, url_for
from flask_restful import Resource, Api
from flasgger import Swagger, swag_from
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from Service.jwt_service import JWTService
from string_helper import is_email
import urllib
import hashlib
import httpx

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
params = urllib.parse.quote_plus(app.config['DEFAULTCONNECTION'])
app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc:///?odbc_connect=%s" % params

api = Api(app)

template = {
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    },
    "security": [
        {"Bearer": []}
    ]
}
swagger = Swagger(app, template=template)
db = SQLAlchemy(app)
jwt_service = JWTService(app.config['SIGNING_KEY'])

@app.route('/')
def home():
    return redirect('/apidocs/')

@app.route("/api/Test")
def hello_world():
    """
    Hello World
    ---
    responses:
      200:
        description: 
    """
    return jsonify({'message': 'Hello World!'}), 200

@app.route("/api/signup", methods=['POST'])
def sign_up():
    """
    會員-註冊會員
    ---
    parameters:
      - in: body
        name: body
        schema:
          id: UserSignUp
          required:
            - name
            - email
            - password
            - cfm_Password
          properties:
            name:
              type: string
              description: 名稱
            email:
              type: string
              description: Email
            password:
              type: string
              description: 密碼
            cfm_password:
              type: string
              description: 再次輸入密碼
    responses:
      200:
        description: 
    """
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        cfm_password = data.get('cfm_password')

        if not name or not email or not password or not cfm_password:
            return {'message': '輸入參數錯誤'}, 400
        if not is_email(email):
            return {'message': 'Email格式錯誤'}, 400
        if password != cfm_password:
            return {'message': '請檢查密碼是否輸入錯誤'}, 400
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return {'message': 'Email已經註冊過了'}, 400

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        new_user = User(name=name, email=email,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return {'message': '註冊完成', 'user': {'id': new_user._id, 'name': new_user.name, 'email': new_user.email}}, 200
    except Exception as e:
        return {'message':  str(e)}, 400

@app.route("/api/signin", methods=['POST'])
def sign_in():
    """
    會員-登入會員
    ---
    parameters:
      - in: body
        name: body
        schema:
          id: UserSignIn
          required:
            - email
            - password
          properties:
            email:
              type: string
              description: Email
            password:
              type: string
              description: 密碼
    responses:
      200:
        description: 
    """
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return {'message': '輸入參數錯誤'}, 400
        if not is_email(email):
            return {'message': 'Email格式錯誤'}, 400
        
        user = User.query.filter_by(email=email).first()
        if user is None:
            return {'message': '查無此會員'}, 400

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if user.password != hashed_password:
            return {'message': '密碼錯誤'}, 400
        
        payload = {
        'user_id': user._id
        }
        token = jwt_service.create_token(payload)

        return {'token': token}, 200
    except Exception as e:
        return {'message':  str(e)}, 400
    
@app.route("/api/user")
@jwt_service.jwt_required
def user(current_user):
    """
    會員-取得會員資訊
    ---
    responses:
      200:
        description: 
        schema:
          type: object
          properties:
            user:
              type: object
              properties:
                id:
                  type: string
                  description: 使用者Id
                name:
                  type: string
                  description: 使用者名稱
                email:
                  type: string
                  description: 使用者Email
    """
    try:
        user = User.query.filter_by(_id=current_user['user_id']).first()
        if user is None:
            return {'message': '查無此會員'}, 400
        return {'user': {'id': user._id, 'name': user.name, 'email': user.email}}, 200

    except Exception as e:
        return {'message':  str(e)}, 400
    
@app.route("/api/user/update", methods=['POST'])
@jwt_service.jwt_required
def update_user(current_user):
    """
    會員-更新會員資訊
    ---
    parameters:
      - in: body
        name: body
        schema:
          id: UpdateUser
          required:
            - name
          properties:
            name:
              type: string
              description: 使用者名稱    
    responses:
      200:
        description: 
        schema:
          type: object
          properties:
            user:
              type: object
              properties:
                id:
                  type: string
                  description: 使用者Id
                name:
                  type: string
                  description: 使用者名稱
                email:
                  type: string
                  description: 使用者Email
    """
    try:
        user = User.query.get(current_user['user_id'])
        name = request.json['name']
        if not name:
            return {'message': '輸入參數錯誤'}, 400
        if user is None:
            return {'message': '查無此會員'}, 400
        
        user.name = name
        db.session.commit()

        return {'message':'更新完成','user': {'id': user._id, 'name': user.name, 'email': user.email}}, 200

    except Exception as e:
        return {'message':  str(e)}, 400    
    
@app.route("/api/WeatherForecast")
@jwt_service.jwt_required
def weather_forecast(current_user):
    """
    API-取得天氣資訊
    ---
    responses:
      200:
        description: 
    """
    try:
        with httpx.Client(verify=False) as client:
          response = client.get(f"{app.config['API_DOMAIN']}/WeatherForecast")
          if response.status_code == 200:
            data = response.json()
            return data
          else:
            raise Exception("API 執行失敗")
    except Exception as e:
        return {'message':  str(e)}, 400    

class User(db.Model):
    _id = db.Column('Id', db.Integer, primary_key=True)
    name = db.Column('UserName', db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    def __init__(self, name, email,password):
        self.name =name
        self.email = email
        self.password = password



