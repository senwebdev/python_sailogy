from rest_framework import serializers
from accounts.models import User
from lib.utils import validate_email as email_is_valid


class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.CharField()

    class Meta:
        model = User
        fields = ('uuid', 'email', 'first_name', 'last_name',
                  'password', 'profile_picture', 'is_active')

    def create(self, validated_data): 
        user = User.objects.create(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user 
 
    def validate_email(self, value):
        if not email_is_valid(value):
            raise serializers.ValidationError(
                    'Please use a different email address provider.') 

        return value
 

class UserRegistrationGoogleSerializer(UserRegistrationSerializer):
    class Meta(UserRegistrationSerializer.Meta):
        model = User
        fields = UserRegistrationSerializer.Meta.fields +\
            ('google_user_id', 'google_access_token', 'google_refresh_token',
             'google_access_token_expiration_date')


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'uuid', 'profile_picture',
                  'email', 'is_active')
