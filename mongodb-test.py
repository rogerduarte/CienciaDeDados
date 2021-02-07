from pymongo import MongoClient
from random import randint

"""
Test connection to MongoDB database and insert some data
https://www.mongodb.com/blog/post/getting-started-with-python-and-mongodb
"""

url = "mongodb://192.168.0.19:27017/"
client = MongoClient(url)
db = client.business
# Step 2: Create sample data
names = ['Kitchen', 'Animal', 'State', 'Tastey', 'Big', 'City', 'Fish', 'Pizza', 'Goat', 'Salty', 'Sandwich', 'Lazy',
         'Fun']
company_type = ['LLC', 'Inc', 'Company', 'Corporation']
company_cuisine = ['Pizza', 'Bar Food', 'Fast Food', 'Italian', 'Mexican', 'American', 'Sushi Bar', 'Vegetarian']
for x in range(1, 501):
    business = {
        'name': names[randint(0, (len(names) - 1))] + ' ' + names[randint(0, (len(names) - 1))] + ' ' + company_type[
            randint(0, (len(company_type) - 1))],
        'rating': randint(1, 5),
        'cuisine': company_cuisine[randint(0, (len(company_cuisine) - 1))]
    }
    # Step 3: Insert business object directly into MongoDB via isnert_one
    result = db.reviews.insert_one(business)
    # Step 4: Print to the console the ObjectID of the new document
    print('Created {0} of 500 as {1}'.format(x, result.inserted_id))
# Step 5: Tell us that you are done
print('finished creating 500 business reviews')
