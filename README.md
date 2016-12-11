#Udacity Multi User Blog project

This is my multi user blog project site. I tried to reach the specifications for this site:
* accounts passwords are stored in sha256 format with secret word
* only registered accounts can create, like, remove and edit posts.

Design is bad, but at least i used bootstrap :)


Project is available on: https://udacity-multiblog-project.appspot.com.

It also can be run locally with `dev_appserver.py path_to_project/` command. Or if you need to clear the datastore, use ` dev_appserver.py --clear_datastore=yes 3_multi_user_blog/project/`.

If you haven't installed gcloud yet, please install [Google App Engine SDK](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python) for python

I also created test account: udacity/udacity for preview and some sample posts.