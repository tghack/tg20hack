# Writeup [Professor Doctrina](README.md)

## Challenge description
**Author: odin**

**Difficulty: easy**

**Category: misc** 

---

Professor Doctrina has developed a secret formula to speed up the plant's growth by using crystals. Rumors say that this formula can be used to create bombs, and threaten the peace on the ship. Can you pass Doctrinas authentication system, and find out if the rumors are true. The website uses some kind of pattern-based check, and a model used by the website was leaked at an underground forum.

- [model.pkl](uploads/model.pkl)

## Writeup

First, the challenge description and the challenge website indicate that it is a machine that validates the password input. 
The model used for validation is given as a part of the challenge.



1. Based on the file extension of `model.pkl` we can assume that the file is a python pickle object. When trying to unpickle the file you might get an error if you don't have the `sklearn` package installed. After installing `sklearn` with `pip3 install --user sklearn` you get an object of type `DecisionTreeClassifier`.
2. A method that can be used to get a more structured understanding of the model, is to visualize the Decision Tree. (https://scikit-learn.org/stable/modules/tree.html)
3. Using the code snippet below makes it possible to generate this tree structure into a PDF formatted file.


```
#! /usr/bin/env python3

import pickle
import sys
from sklearn.tree import export_graphviz
import graphviz

clf = pickle.load(open(sys.argv[1], "rb"))

out_data = export_graphviz(clf, out_file=None)
graph = graphviz.Source(out_data)
graph.render("tree")
```

This shows that there is one condition that provides one unique output, and the rest
of the tree can be ignored. It is possible to assume that this is related to
pass or not pass in the authentication method.

4. If one looks closer to the source code of the webpage, it is possible to find code that writes the following to the output console.



```
console.log("{&#39;password_length&#39;: 3, &#39;uppercase_count&#39;: 0, &#39;lowercase_count&#39;: 3, &#39;numeric_count&#39;: 0, &#39;special_count&#39;: 0}");

```

5. Using these variables as columns into the method makes it possible to generate a graph that contains the password constraints.


```

#! /usr/bin/env python3

import pickle
import sys
from sklearn.tree import export_graphviz
import graphviz


clf = pickle.load(open(sys.argv[1], "rb"))

col_names=["password_length", "uppercase_count", "lowercase_count", "numeric_count", "special_count"]



out_data = export_graphviz(clf, out_file=None,
                        filled=True, rounded=True,
                        special_characters=True, feature_names = col_names,class_names=['0','1'])
graph = graphviz.Source(out_data)
graph.render("tree")

```

7. Based on the PDF output, the constraints are: 
    1. Longer than 17.5 
    2. More than 1.5 uppercase
    3. Shorter than 18.5
    4. More than 13.5 lowercase
    5. More than one number
8. A possible password based on the pattern is: aaaaaaaaaaaaaa11AA
9. Using this password reveals the flag

```
TG20{patterns_not_secured_by_AI}
```
