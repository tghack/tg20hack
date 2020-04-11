# Load libraries
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
import pickle

col_names = ["password_length", "uppercase_count", "lowercase_count", "special_count", "numeric_count", "label"]
# load dataset
df = pd.read_csv("password.csv", header=None, names=col_names)


X = df[col_names[:-1]]
y = df.label

# Create Decision Tree classifer object
clf = DecisionTreeClassifier()

# Train Decision Tree Classifer
clf = clf.fit(X, y)
pickle.dump(clf, open("../static/model.pkl", 'wb'))

