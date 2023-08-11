import jwt
from functools import wraps
from flask import request

class JWTService:
    def __init__(self, signing_Key):
        self.signing_Key = signing_Key

    def create_token(self, payload):
        token = jwt.encode(payload, self.signing_Key, algorithm='HS256')
        return token
    
    def jwt_required(self,f):
        #保留封裝前function的資訊，否則因為最後執行的是decorated_function，會顯示decorated_function的資訊
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                token = request.headers['Authorization'][len("Bearer "):].strip()
            if not token:
                return {'message': '未正確登入'}, 403
            try:
                data = jwt.decode(token, self.signing_Key, algorithms=['HS256'])
                current_user = data
            except:
                return {'message': '無效的存取權限'}, 403
            return f(current_user, *args, **kwargs)
        return decorated_function