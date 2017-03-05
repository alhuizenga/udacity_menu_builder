# udacity_menu_builder
"# udacity_menu_builder" 
"# udacity_menu_builder" 

A Python module that uses the PostgreSQL database to keep track of players and matches in a [Swiss-system tournament](https://en.wikipedia.org/wiki/Swiss-system_tournament).

# Files

* **tournament.sql:** Database schema. Defines SQL tables and views.
* **tournament.py:** Defines functions for tracking tournament progress.

# Running the module

1. Install Python 2 and PostgreSQL.
2. Ensure that the following Python modules are installed: psycopg2, bleach.
3. Create a database called tournament, and run tournament.sql to create the schema.
4. To run unit tests, run tournament_test.py.

# Schema (tournament.sql)

* **player:** Table. Rows contain player ID and name.
* **match:** Table. Rows contain match ID, player ID of the winner, player ID of the loser.
* **wins:** View. Rows contain player ID, name, number of matches won.
* **matches:** View. Rows contain player ID, name, number of matches played.
* **standings:** View. Rows contain player ID, name, number of wins, number of matches won.

# Functions (tournament.py)

* **connect:** Connects to the tournament database.
* **deleteMatches:** Deletes all matches from the tournament database.
* **deletePlayers:** Deletes all matches from the tournament database.
* **countPlayers:** Returns the number of players currently registered.
* **registerPlayer:** Adds a player to the tournament database.
* **playerStandings:** Returns a list of the players and their win records, sorted by wins.
* **reportMatch:** Records the outcome of a single match between two players.
* **swissPairings:** Returns a list of pairs of players for the next round of a match.
