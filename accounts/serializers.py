from rest_framework import serializers
from .models import CustomUser,Role



class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id','name']

class CustomUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = [ 'email', 'password','keycloak_id','is_verified','is_suspended','account_type','date_joined']

    

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user



