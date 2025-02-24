from src.db import DBMethods
from flask import Flask, render_template

app = Flask(__name__)


@app.route('/')
def index():
    try:
        db = DBMethods()
        db.read_configuration()
        db.create_tables()
        db.synchronize_data()
        data = db.retrieve_composite_feed()
        return render_template('index.html', data=data)
    except Exception as e:
        return render_template('error.html', error=e)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)