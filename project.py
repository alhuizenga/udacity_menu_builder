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


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Udacity Menu Builder"


engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Get the one-time-secret code from the login page and authenticate
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
    result = json.loads(h.request(url, 'GET')[1])
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
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
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
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], 
                    email=login_session['email'], 
                    picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Drop the oauth session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['credentials']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: ' 
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['credentials']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['credentials'] 
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
    
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


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
def newRestaurant():
    if 'user_id' not in login_session:
        return redirect('login')
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
def editRestaurant(restaurant_id):
    if 'user_id' not in login_session:
        return redirect('login')
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    if request.method == 'POST':
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
        restaurant.name = request.form['name']
        session.commit()
        flash("{} has been updated!".format(restaurant.name))
        return redirect(url_for('restaurants'))
    else:
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
        return render_template('edit_restaurant.html', restaurant=restaurant, user=user)


# Delete a restaurant
@app.route('/restaurants/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    if 'user_id' not in login_session:
        return redirect('login')
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    if request.method == 'POST':
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
        session.delete(restaurant)
        session.commit()
        flash("{} has been deleted!".format(restaurant.name))
        return redirect(url_for('restaurants'))
    else:
        restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
        return render_template('delete_restaurant.html', restaurant=restaurant, user=user)


# Return the menu for a restaurant (application)
@app.route('/restaurants/<int:restaurant_id>/')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    appetizers = session.query(MenuItem).filter_by(restaurant_id=restaurant_id, course='Appetizer').all()
    entrees = session.query(MenuItem).filter_by(restaurant_id=restaurant_id, course='Entree').all()
    desserts = session.query(MenuItem).filter_by(restaurant_id=restaurant_id, course='Dessert').all()
    beverages = session.query(MenuItem).filter_by(restaurant_id=restaurant_id, course='Beverage').all()
    if 'user_id' in login_session:
        user = session.query(User).filter_by(id=login_session['user_id']).one()
        return render_template('menu.html', 
                                user=user,
                                restaurant=restaurant,
                                appetizers=appetizers,
                                entrees=entrees,
                                desserts=desserts,
                                beverages=beverages)
    else:
        return render_template('menu.html',
                                restaurant=restaurant,
                                appetizers=appetizers,
                                entrees=entrees,
                                desserts=desserts,
                                beverages=beverages)


# Return the menu for a restaurant (endpoint)
@app.route('/restaurants/<int:restaurant_id>/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
    return jsonify(MenuItems=[i.serialize for i in items])


# Add a new menu item for a restaurant
@app.route('/restaurants/<int:restaurant_id>/new/',
            methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return redirect('login')
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
def editMenuItem(restaurant_id, item_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return redirect('login')
    user = session.query(User).filter_by(id=login_session['user_id']).one()
    if request.method == 'POST':
        item = session.query(MenuItem).filter_by(id=item_id).one()
        item.name = request.form['name']
        item.description = request.form['description']
        item.course = request.form['course']
        item.price = request.form['price']
        session.commit()
        flash("{} has been updated!".format(item.name))
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant.id))
    else:
        item = session.query(MenuItem).filter_by(id=item_id).one()
        return render_template('edit_item.html', 
                                item=item,
                                restaurant=restaurant, 
                                user=user)


# Delete a menu item for a restaurant
@app.route('/restaurants/items/<int:item_id>/delete/',
            methods=['GET', 'POST'])
def deleteMenuItem(item_id):
    if 'username' not in login_session:
        return redirect('login')
    username = login_session['username']
    user_id = login_session['user_id']    
    if request.method == 'POST':
        item = session.query(MenuItem).filter_by(id=item_id).one()
        session.delete(item)
        session.commit()
        flash("{} has been deleted!".format(item.name))
        return redirect(url_for('restaurantMenu', restaurant_id=item.restaurant_id))
    else:
        item = session.query(MenuItem).filter_by(id=item_id).one()
        return render_template('delete_item.html', 
                                item=item, 
                                username=username,
                                restaurant_id=item.restaurant_id)


# Get a single menu item (endpoint)
@app.route('/restaurants/items/<int:item_id>/JSON/')
def getMenuItem(item_id):
    item = session.query(MenuItem).filter_by(id=item_id).one()
    return jsonify(MenuItem=[item.serialize])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
