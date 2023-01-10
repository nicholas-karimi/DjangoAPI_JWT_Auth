import jwt, datetime 
from json import JSONEncoder
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed


from .serializers import UserSerializer
from .models import User

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)



class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User Not Found!')

        if not user.check_password(password):
            raise AuthenticationFailed("Incorrect Password")
        

        # jwt
        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            # 'exp': 648490,
            'iat': datetime.datetime.utcnow()
            # 'iat': 628490
        }

        class DateTimeEncoder(JSONEncoder):
            # overide default method
            def default(self, obj):
                if isinstance(obj, (datetime.date, datetime.datetime)):
                    return obj.isoformat()

        token = jwt.encode(payload, "secret", algorithm="HS256")
        # print(DateTimeEncoder().encode(payload))
        # return Response(
        #     {
        #         'jwt': token
        #     }
        # )
        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        # decode
        if not token:
            raise AuthenticationFailed("Not Authenticated")

        try:
            payload = jwt.decode(token, "secret", algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Not Authenticated")


        user = User.objects.filter(id=payload['id']).first()
        
        serializer = UserSerializer(user)

        return Response(serializer.data)


class LogoutView(APIView):
    def get(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            "message": "Logout Successful!"
        }

        return response