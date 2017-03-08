from flask import Flask, render_template, url_for, request, redirect, flash, jsonify
from flask import session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import random, string
from database_setup import Base, Restaurant, MenuItem, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Udacity Menu Builder"


engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Decorator for checking user login status
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


# Create anti-forgery state token
@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Get the one-time-secret code from the login page and authenticate with Facebook
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"

    # strip expire tag from access token
    token = result.split("&")[0]
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


# Drop the Facebook oauth session
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Get the one-time-secret code from the login page and authenticate with Google
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode("utf8"))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '''
    " style = "width: 300px; height: 300px;
    border-radius: 150px;-webkit-border-radius: 150px;
    -moz-border-radius: 150px;">
    '''
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Drop the Google oauth session
@app.route('/gdisconnect')
def gdisconnect():
    if 'credentials' not in login_session:
        print 'No access token'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = login_session['credentials']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['credentials']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been signed out.")
        return redirect(url_for('restaurants'))
    else:
        flash("You were not logged in")
        return redirect(url_for('restaurants'))


# User Helper Functions

# Save the session user to the database
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Retrieve the session user from the database
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Look up user by email address
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Return a list of restaurants (application)
@app.route('/')
@app.route('/restaurants/')
def restaurants():
    restaurants = session.query(Restaurant).order_by(Restaurant.name).all()
    if 'user_id' in login_session:
        user = session.query(User).filter_by(id=login_session['user_id']).one()
        return render_template('restaurants.html', restaurants=restaurants, user=user)
    else:
        return render_template('restaurants.html', restaurants=restaurants)


# Return a list of restaurants (endpoint)
@app.route('/restaurants/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(Restaurants=[r.serialize for r in restaurants])


# Add a new restaurant
@app.route('/restaurants/new/', methods=['GET', 'POST'])
@login_required
def newRestaurant():
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    if request.method == 'POST':
        new_restaurant = Restaurant(name=request.form['name'], user_id=user.id)
        session.add(new_restaurant)
        session.commit()
        flash("Added a new restaurant called {}!".format(new_restaurant.name))
        return redirect(url_for('restaurants'))
    else:
        return render_template('new_restaurant.html', user=user)


# Edit a restaurant name
@app.route('/restaurants/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
@login_required
def editRestaurant(restaurant_id):
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    if not restaurant:
        return redirect(url_for('restaurants'))
    if login_session['user_id'] != restaurant.user_id:
        return redirect(url_for('restaurants'))
    if request.method == 'POST':
        restaurant.name = request.form['name']
        session.commit()
        flash("{} has been updated!".format(restaurant.name))
        return redirect(url_for('restaurants'))
    else:
        return render_template('edit_restaurant.html', restaurant=restaurant, user=user)


# Delete a restaurant
@app.route('/restaurants/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteRestaurant(restaurant_id):
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    if not restaurant:
        return redirect(url_for('restaurants'))
    if login_session['user_id'] != restaurant.user_id:
        return redirect(url_for('restaurants'))
    if request.method == 'POST':
        session.delete(restaurant)
        session.commit()
        flash("{} has been deleted!".format(restaurant.name))
        return redirect(url_for('restaurants'))
    else:
        return render_template('delete_restaurant.html', restaurant=restaurant, user=user)


# Return the menu for a restaurant (application)
@app.route('/restaurants/<int:restaurant_id>/')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    if not restaurant:
        return redirect(url_for('restaurants'))
    appetizers = session.query(MenuItem).filter_by(restaurant_id=restaurant_id,
                                                   course='Appetizer').all()
    entrees = session.query(MenuItem).filter_by(restaurant_id=restaurant_id,
                                                course='Entree').all()
    desserts = session.query(MenuItem).filter_by(restaurant_id=restaurant_id,
                                                 course='Dessert').all()
    beverages = session.query(MenuItem).filter_by(restaurant_id=restaurant_id,
                                                  course='Beverage').all()
    creator = getUserInfo(restaurant.user_id)
    if 'user_id' in login_session:
        user = session.query(User).filter_by(id=login_session['user_id']).one()
        return render_template('menu.html',
                               user=user,
                               restaurant=restaurant,
                               appetizers=appetizers,
                               entrees=entrees,
                               desserts=desserts,
                               beverages=beverages,
                               creator=creator)
    else:
        return render_template('menu.html',
                               restaurant=restaurant,
                               appetizers=appetizers,
                               entrees=entrees,
                               desserts=desserts,
                               beverages=beverages,
                               creator=creator)


# Return the menu for a restaurant (endpoint)
@app.route('/restaurants/<int:restaurant_id>/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    if not restaurant:
        return 'No restaurant with that ID'
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
    return jsonify(MenuItems=[i.serialize for i in items])


# Add a new menu item for a restaurant
@app.route('/restaurants/<int:restaurant_id>/new/',
           methods=['GET', 'POST'])
@login_required
def newMenuItem(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    if not restaurant:
        return redirect(url_for('restaurants'))
    if login_session['user_id'] != restaurant.user_id:
        return redirect(url_for('restaurants'))
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    if request.method == 'POST':
        new_item = MenuItem(name=request.form['name'],
                            restaurant_id=restaurant_id,
                            description=request.form['description'],
                            course=request.form['course'],
                            price=request.form['price'])
        session.add(new_item)
        session.commit()
        flash("{} added to the menu!".format(new_item.name))
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('new_item.html',
                               restaurant=restaurant,
                               user=user)


# Edit a menu item for a restaurant
@app.route('/restaurants/<int:restaurant_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editMenuItem(restaurant_id, item_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    item = session.query(MenuItem).filter_by(id=item_id).first()
    if login_session['user_id'] != restaurant.user_id:
        return redirect(url_for('restaurants'))
    if not restaurant:
        return redirect(url_for('restaurants'))
    if not item:
        return redirect(url_for('restaurants'))
    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.course = request.form['course']
        item.price = request.form['price']
        session.commit()
        flash("{} has been updated!".format(item.name))
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant.id))
    else:
        return render_template('edit_item.html',
                               item=item,
                               restaurant=restaurant,
                               user=user)


# Delete a menu item for a restaurant
@app.route('/restaurants/<int:restaurant_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteMenuItem(restaurant_id, item_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    item = session.query(MenuItem).filter_by(id=item_id).first()
    if login_session['user_id'] != restaurant.user_id:
        return redirect(url_for('restaurants'))
    if not restaurant:
        return redirect(url_for('restaurants'))
    if not item:
        return redirect(url_for('restaurants'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("{} has been deleted!".format(item.name))
        return redirect(url_for('restaurantMenu', restaurant_id=item.restaurant_id))
    else:
        return render_template('delete_item.html',
                               item=item,
                               user=user,
                               restaurant=restaurant)


# Get a single menu item (endpoint)
@app.route('/restaurants/items/<int:item_id>/JSON/')
def getMenuItemJSON(item_id):
    item = session.query(MenuItem).filter_by(id=item_id).first()
    if not item:
        return 'No item with that ID'
    return jsonify(MenuItem=[item.serialize])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
