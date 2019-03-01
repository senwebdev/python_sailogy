from rest_framework import status, parsers, renderers
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import CreateModelMixin
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.serializers import JSONWebTokenSerializer
from rest_framework_jwt.utils import jwt_response_payload_handler
from accounts.serializers import UserRegistrationGoogleSerializer
from lib.utils import AtomicMixin, get_html_str
from rest_framework_jwt.settings import api_settings
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from accounts.models import User, SlackInstall
from base.models import Project, Artifact, UserArtifact,\
    Invitation, UserProject
from base.views import tell_slack_user_to_signup,\
    auth_and_get_identity_details_in_slack
from django.utils import timezone
import requests
import os
import analytics
import uuid
import json


# This is for registering a TEAM, not a user
class RegisterSlackView(AtomicMixin, CreateModelMixin, GenericAPIView):
    authentication_classes = ()
    permission_classes = ()
    renderer_classes = (renderers.StaticHTMLRenderer,)

    def get(self, request):
        code = request.GET.get('code', False)

        if code is False:
            return Response(
                    "No code supplied.",
                    status=status.HTTP_401_UNAUTHORIZED)

        payload = {'code': code,
                   'client_id': settings.SLACK_CLIENT_ID,
                   'client_secret': settings.SLACK_CLIENT_SECRET}
        r = requests.get(settings.SLACK_OAUTH_URL + "oauth.access",
                         params=payload)
        if r.status_code != 200:
            return Response(
                    "Problem with authenticating with Slack.",
                    status=status.HTTP_401_UNAUTHORIZED)

        oar = r.json()
        # print(json.dumps(oar, indent=4))

        # Get the team name so we can redirect them to the
        # right place
        payload = {'token': oar['bot']['bot_access_token']}
        r = requests.get(settings.SLACK_OAUTH_URL + "team.info",
                         params=payload)
        if r.status_code != 200:
            return Response(
                    "Problem with getting team info.",
                    status=status.HTTP_401_UNAUTHORIZED)

        tr = r.json()

        # Save details
        # If we have an existing record for that
        # bot user id, team id, and team domain
        # combo, just update its access token.
        try:
            si = SlackInstall.objects.get(
                    bot_user_id=oar['bot']['bot_user_id'],
                    team_id=tr['team']['id'],
                    team_domain=tr['team']['domain']
            )

            si.bot_access_token = oar['bot']['bot_access_token']
            si.access_token = oar['access_token']
            si.save()

        # Else, create it
        except ObjectDoesNotExist:
            si = SlackInstall(
                    bot_user_id=oar['bot']['bot_user_id'],
                    bot_access_token=oar['bot']['bot_access_token'],
                    access_token=oar['access_token'],
                    team_id=tr['team']['id'],
                    team_domain=tr['team']['domain']
            )
            si.save()

        # 1 - We'll first DM the user who installed the app
        user_id_of_installer = auth_and_get_identity_details_in_slack(
            si.access_token)['user_id']
        tell_slack_user_to_signup(si.bot_access_token, user_id_of_installer)

        # Spit out JS back to the client and have it redirect
        # to their slack page
        data = """
            <script type="text/javascript">
            window.location='https://braidhq.com/slack-yay/'
            </script>
        """

        return Response(data, status=status.HTTP_200_OK)


class UserRegisterGoogleView(AtomicMixin, CreateModelMixin, GenericAPIView):
    serializer_class = UserRegistrationGoogleSerializer
    authentication_classes = ()
    permission_classes = ()
    renderer_classes = (renderers.StaticHTMLRenderer,)

    def get(self, request):
        # Check for presence of 'code' query param. Complain
        # if not found
        code = request.GET.get('code', False)
        state = request.GET.get('state', False)

        if code is False:
            return Response(
                    "No code supplied.",
                    status=status.HTTP_401_UNAUTHORIZED)
        elif state is False:
            return Response(
                    "No state from client supplied.",
                    status=status.HTTP_401_UNAUTHORIZED)

        # Decompose state
        state = json.loads(state)

        # Turn in code for tokens
        payload = {'code': code,
                   'client_id': settings.GOOGLE_CLIENT_ID,
                   'client_secret': settings.GOOGLE_CLIENT_SECRET,
                   'redirect_uri': settings.GOOGLE_REDIRECT_URI,
                   'grant_type': 'authorization_code'}
        r = requests.post(settings.GOOGLE_OAUTH_URL + '/token',
                          params=payload)
        jr = r.json()

        # Check for presence of tokens Complain if not found
        # NOTE - refresh token only comes on very first
        # authorization
        if 'access_token' not in jr:
            error = "No access token given by Google"
            return Response(get_html_str(error),
                            status=status.HTTP_400_BAD_REQUEST)
            # return Response(
            #     error,
            #     status=status.HTTP_401_UNAUTHORIZED)

        refresh_token = None
        if 'refresh_token' in jr:
            refresh_token = jr['refresh_token']
        
        access_token = jr['access_token']
        google_access_token_expiration_date = timezone.now() +\
            timezone.timedelta(seconds=jr['expires_in'])

        # Get user info
        payload = {'alt': 'json',
                   'access_token': access_token}
        r = requests.get(settings.GOOGLE_OAUTH_URL + '/userinfo',
                         params=payload)
        # print(r.url)
        jr = r.json()
        # print(jr)

        # To prevent a user from opening one gmail account and oauthing
        # into another, we take the email address linked to the logged in
        # account and compare it to the oauth one. If they don't match,
        # spit an error.
        if state['email'] != jr['email'] and state['source'] == "gmail":
            error = "You are oauthing an account different from " +\
                     "the one you are currently logged into in your browser"
            return Response(error,
                            status=status.HTTP_400_BAD_REQUEST)
        elif state['email'] != jr['email'] and state['source'] == "slack":
            error = "You are oauthing an account different from " +\
                     "the one you are using for Slack"
            return Response(error,
                            status=status.HTTP_400_BAD_REQUEST)
        
        user = None
        urs = None
        data = {}
        data['first_name'] = jr['given_name']
        data['last_name'] = jr['family_name']
        data['email'] = jr['email']
        data['password'] = 'default'
        data['google_user_id'] = jr['sub']
        data['google_access_token'] = access_token
        data['google_access_token_expiration_date'] =\
            google_access_token_expiration_date
        data['profile_picture'] = jr['picture']
        new_user = False
        invited = False

        try:
            user = User.objects.get(email=jr['email'])
            # If a user a already member of braid
            if user.is_active is True:
                # If they have a profile on our system and we get
                # refresh token, this means they've already authorized
                # in the past. So just update their info on our system.
                # Credit: http://stackoverflow.com/questions/10827920/
                #        not-receiving-google-oauth-refresh-token
                if refresh_token is not None:
                    data['google_refresh_token'] = refresh_token
                data['is_active'] = True
                urs = self.serializer_class(user, data=data)
            # If a user is a pending user
            else:
                new_user = True
                invited = True
                data['google_refresh_token'] = refresh_token
                data['is_active'] = True
                # data['date_joined'] = 
                urs = self.serializer_class(user, data=data)
                self.send_welcome_mail(data['email'])    
            

        # New user completely?
        except ObjectDoesNotExist:
            new_user = True
            data['google_refresh_token'] = refresh_token
            data['is_active'] = True
            urs = self.serializer_class(data=data)

            # Send a welcome mail to newly joined braid user!
            self.send_welcome_mail(data['email'])

        # Embed JS that calls postmessage and sends a message
        # to who opened us (inject.js)
        if urs.is_valid():
            user = urs.save()

            # Check the invitation table. If we are a new user
            # and we have projects we've already been invited to
            # to, add myself to those projects and delete
            # those invitation records.
            # If there are no invitations for me, create some
            # default projects for me
            if new_user:
                # if Invitation.objects.filter(email=user.email).count() > 0:
                #     for i in Invitation.objects.filter(email=user.email):
                #         up = UserProject(
                #                 inviter=i.inviter, user=user,
                #                 project=i.project,
                #                 owner=i.owner)
                #         up.save()
                #     Invitation.objects.filter(email=user.email).delete()
                # else:

                # If a user is not an invitee of a specific project, just connected to braid simply
                # then create a default project & artifiacts and even comments.
                if not invited:
                    p = Project(name='Side Project Planning', creator=user)
                    p.save()
                    up = UserProject(
                            user=user, project=p,
                            owner=True)
                    up.save()

                    p = Project(name='Career Development', creator=user)
                    p.save()
                    up = UserProject(
                            user=user, project=p,
                            owner=True)
                    up.save()

                    p = Project(name='Upcoming Trips', creator=user)
                    p.save()
                    up = UserProject(
                            user=user, project=p,
                            owner=True)
                    up.save()

                    # Three artifacts in this one
                    p = Project(name='To Do', creator=user)
                    p.save()
                    up = UserProject(
                            user=user, project=p,
                            owner=True, unread_update_count=3)
                    up.save()

                    a = Artifact(
                            project=p,
                            body='Create Braid account',
                            preview='Create Braid account',
                            creator=user,
                            source=Artifact.Source.NOTE,
                            status=Artifact.Status.COMPLETE)
                    a.save()
                    ua = UserArtifact(
                            user=user,
                            artifact=a, unread_update_count=1)
                    ua.save()

                    a = Artifact(
                            project=p,
                            body='Call mom',
                            preview='Call mom',
                            creator=user,
                            source=Artifact.Source.NOTE)
                    a.save()
                    ua = UserArtifact(
                            user=user,
                            artifact=a, unread_update_count=1)
                    ua.save()

                    a = Artifact(
                            project=p,
                            body='Remember to exercise',
                            preview='Remember to exercise',
                            creator=user,
                            source=Artifact.Source.NOTE,
                            status=Artifact.Status.IN_PROGRESS)
                    a.save()
                    ua = UserArtifact(
                            user=user,
                            artifact=a, unread_update_count=1)
                    ua.save()

            jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)

            # If the user came from slack...
            browser_msg = ""
            if state['source'] == "slack":
                # Call identify on em for segment
                analytics.identify(str(user.pk), {
                    'email': user.email,
                    'name': user.first_name + " " + user.last_name
                })

                # Message for the browser after they have oauth'd
                browser_msg = """
                    You've successfully created an account on Braid.
                    Check your DMs for more instructions"""

                # DM them onboarding instructions

                # MESSAGE 1
                payload = {'token': state['bot_access_token'],
                           'as_user': True,
                           'channel': state['slack_user_id'],
                           "text": "Welcome to Braid! Braid is the " +
                                   "easiest way to store and share " +
                                   "what's important."}
                r = requests.get(
                        settings.SLACK_OAUTH_URL + "chat.postMessage",
                        params=payload)

                # MESSAGE 2
                callback_id = str(uuid.uuid4())
                redis = settings.REDIS
                redis.set(
                    callback_id,
                    json.dumps({})
                )
                redis.expire(callback_id, 60*60*24)

                attachment =\
                    [
                        {
                            "text": "",
                            "attachment_type": "default",
                            "callback_id": callback_id,
                            "actions": [
                                {
                                    "name": "onboard-button",
                                    "text": "Yes!",
                                    "type": "button",
                                    "style": "primary",
                                    "value": "onboard-show-projects"
                                    },
                                {
                                    "name": "onboard-button",
                                    "text": "Nah, I'm good.",
                                    "type": "button",
                                    "style": "danger",
                                    "value": "onboard-close"
                                },
                            ]
                        }
                    ]
                attachment = json.dumps(attachment)
                payload = {'token': state['bot_access_token'],
                           'as_user': True,
                           'channel': state['slack_user_id'],
                           "text": "To get you started, we've made " +
                                   "three projects for you. Wanna see " +
                                   "them?",
                           'attachments': attachment}
                r = requests.get(
                        settings.SLACK_OAUTH_URL + "chat.postMessage",
                        params=payload)

            data = browser_msg +\
                """
                <script type="text/javascript">
                window.opener.postMessage({'token': '""" + token +\
                """', 'email': '""" + user.email +\
                """'}, 'https://mail.google.com');
                window.close();
                </script>
            """
            return Response(data, status=status.HTTP_200_OK)

        else:
            return Response(get_html_str(urs.errors),
                            status=status.HTTP_401_UNAUTHORIZED)
    
    def send_welcome_mail(self, email):
        # SEND EMAIL TO NEW USER

        # There will be two inline images in the email. Download
        # them.
        remote_path = settings.AWS_HOSTNAME + "/" +\
            settings.AWS_STORAGE_BUCKET_NAME + "/" +\
            "email_assets/Add-to-Braid-button.png"
        add_btn_file = "/tmp/add-button.png"

        with open(add_btn_file, "wb") as file:
            response = requests.get(remote_path)
            file.write(response.content)
            file.close()

        remote_path = settings.AWS_HOSTNAME + "/" +\
            settings.AWS_STORAGE_BUCKET_NAME + "/" +\
            "email_assets/Braid201-cropped-100pxtall.png"
        logo_file = "/tmp/logo.png"

        with open(logo_file, "wb") as file:
            response = requests.get(remote_path)
            file.write(response.content)
            file.close()

        files = [("inline[0]", open(logo_file, "rb")),
                    ("inline[1]", open(add_btn_file, "rb"))]

        # Send registration email here
        email_text = """<html><img src="cid:logo.png"/>
        <br/><br/>
        Hi! Welcome to Braid. Braid is the easiest way to stay
        coordinated on your projects, right inside your email.
        <br/><br/>
        With Braid, it's super easy to add emails, notes,
        files, and meetings to a single shared project stream,
        right from within your email and calendar. Try it now -
        just click the Add to Braid button in your Gmail above!
        <br/><br/>
        <img src="cid:add-button.png"/>
        <br/><br/>
        You can also add others to your projects and
        keep everyone up to the minute with optional task statuses
        and due dates.
        <br/><br/>
        We also have a Braid bot for Slack!  Install it in your teams
        by going to bit.ly/braid-slack .  You can @braid inside Slack
        to learn how the Braid Slack bot works.
        <br/><br/>
        And if you came to Braid from Slack, get the Chrome extension
        to add Braid to Gmail and Google Calendar:
        https://chrome.google.com/webstore/detail/braid/hefhmdpdiemkipkgibpfdikphjibhpok
        <br/><br/>
        If you have any questions, just shoot us a
        note at support@braidtogether.com. We're super excited to
        have you as a Braid member!<br/><br/>
        Cheers,<br/>Team Braid<br/><br/>
        Braid, Inc., 156 2nd Street, San Francisco, CA 94105</html>"""

        url = "https://api.mailgun.net/v3/" +\
            settings.MAILGUN_DOMAIN + "/messages"
        data = {
            'from': 'team@braidtogether.com',
            'to': email,
            'subject': "Welcome to Braid!",
            'html': email_text
            }

        r = requests.post(
                url,
                auth=('api', settings.MAILGUN_API_KEY),
                data=data, files=files)

        os.remove(logo_file)
        os.remove(add_btn_file)


class UserLoginView(APIView):
    throttle_classes = ()
    permission_classes = ()
    authentication_classes = ()
    parser_classes = (parsers.FormParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = JSONWebTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        # TODO: Check if google token is active

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            token = serializer.object.get('token')
            response_data = jwt_response_payload_handler(token, user, request)
            return Response(response_data)

        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
