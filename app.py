import required as required
from flask import Flask, render_template, jsonify, make_response
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from time import time
from random import random
import json
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)


class databaseModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(100), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    dataTime = db.Column(db.String(100), nullable=False)
    error = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return 'hello' #f"Rekord(url = {url}, status_code = {status_code}, dataTime = {dataTime}, error = {error})"


class errorTime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(100), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    dataTime = db.Column(db.String(100), nullable=False)
    error = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return 'hello' #f"Rekord(url = {url}, status_code = {status_code}, dataTime = {dataTime}, error = {error})"


class alliwantALL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(100), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    dataTime = db.Column(db.String(100), nullable=False)
    error = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return 'hello' #f"Rekord(url = {url}, status_code = {status_code}, dataTime = {dataTime}, error = {error})"


class alliwantWRONG(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(100), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    dataTime = db.Column(db.String(100), nullable=False)
    error = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return 'hello' #f"Rekord(url = {url}, status_code = {status_code}, dataTime = {dataTime}, error = {error})"

# pierdolony createall 3eba zawsze odkomentować iedy dodaje się nowy model bazy dla 'utworzenia jej'
#db.create_all()

dane_put_args = reqparse.RequestParser()
dane_put_args.add_argument("name", type=str, help="pomoc dla powodzian", required=True) # to jest wymagane, tak jakby tutaj wypisuje się wymagane argument
dane_put_args.add_argument("slogan", type=str, help="zlomowsiko", required=True) # tu też jak wyżej, jeżeli nie ma czegoś w PUTie to wyświetlany jest help
dane_put_args.add_argument("mordeczka", type=str, help="no jak nie jak tak", required=True) # o tym czy trzeba to załączać decyduje ostatnie 'required'
# relacja z reqparse oddaje wszystkie wymenione dodane argumenty
# tam gdzie jest użyte, dodaje wartości do utworzonej zmiennej danej
# zapis w def-ie jest taki argument[zmienna] (def to apiA)
data = {}


http_put_status_code = reqparse.RequestParser()
# http_put_status_code.add_argument('id', type=int, required=True)
http_put_status_code.add_argument("url", type=str, required=True)
http_put_status_code.add_argument("status_code", type=str, required=False)
http_put_status_code.add_argument("dataTime", type=str, required=True)
http_put_status_code.add_argument("error", type=str, required=False)

http_put_status_code_update = reqparse.RequestParser()
http_put_status_code_update.add_argument("url", type=str)
http_put_status_code_update.add_argument("status_code", type=str)
http_put_status_code_update.add_argument("dataTime", type=str)
http_put_status_code_update.add_argument("error", type=str)

resource_fields = {
    'id': fields.Integer,
    'url': fields.String,
    'status_code': fields.Integer,
    'dataTime': fields.String,
    'error': fields.String
}

###### Tu jest nasza dynamiczna cipeczka

url_check = []
fraud_url = []
#url_check = [{'id': 1, 'url': 'www', 'status_code': '200', 'dataTime': '23:22:34', 'error': 'noWAY'}]

#####

# wyjątki i to co ma być, czyli informacja o tym co jest a czego nie ma ;)
def abort_nie_ma(dane):
    if dane not in data:
        abort(404, message="Nie ma takego rekordu dzbanie")


dane = {"name": {"age": 14, "gender": "male"}}


@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')


@app.route('/NHttp')
def http_number():
    #url_check = [{'id': 1, 'url': 'www', 'status_code': '200', 'dataTime': '23:22:34', 'error': 'noWAY'}]
    basedata = databaseModel.query.all()
    basebase = errorTime.query.all()
    return render_template('visSite.html', item1=basedata, item2=basebase)


@app.route('/NHttp_for_all', methods=["GET", "POST"])
def http_number_all_i_want():
    source1 = alliwantALL.query.all()
    source2 = alliwantWRONG.query.all()
    return render_template('visSiteall.html', item11=source1, item22=source2)


def delete_record(num):
    result = alliwantWRONG.query.filter_by(id=num).one()
    db.session.delete(result)
    db.session.commit()
    return

@app.route('/setData', methods=["GET", "POST"])
def setData():
    data = [time() * 1000, random() * 100]
    response = make_response(json.dumps(data))
    response.content_type = 'application/json'
    return response

nazwy = {'Bartek': {'age': 24, 'gender': 'male'},
         'Monika': {'age': 29, 'gender': 'female'},
         'Marysia': {'age': 27, 'gender': 'female'}}

class api3(Resource):
    def get(self, name):
        return nazwy[name]


class api2(Resource):
    def get(self):
        return {"mleka": "warzywa", "banany": "warzywa"}


class HelloWorld(Resource):
    def get(self):
        return {'dane': 'name'}

    def post(self):
        return {"jem": "ale zapostowalem"}

    def put(self):
        pass

"""
Za pomocą danych poniżej wstawiam dane i je pobieram - ale ze zemnej słownikowej (zapisuje je jako json) 
I towszystko działa elegancko, chyba ten zapis do bazy to bedzie raz na dzień i 3eba się mocno zastanowić co dokładnie
"""

class apiA(Resource):
    def get(self, dane):
        abort_nie_ma(dane)
        return data[dane]

    def put(self, dane):
        args = dane_put_args.parse_args()
        data[dane] = args
        return data[dane], 201

class api_for_http_wrong(Resource):
    @marshal_with(resource_fields)
    def put(self, num):
        args = http_put_status_code.parse_args()
        result = errorTime.query.filter_by(id=num).first()
        if result:
            abort(409, message='Record is taken...')
        miarka = errorTime(id=num, url=args['url'], status_code=args['status_code'], dataTime=args['dataTime'], error=args['error'])
        db.session.add(miarka)
        db.session.commit()
        return miarka, 201


class api_for_hhtp(Resource):
    # udało sie jakoś z kombinatorstwa zrobić to, działało z przykładu z yt i zrobiłem podobnie
    # zapisuje jsona do tablicy, każdy json jako osobny elemet i jest ok 18.01
    # mały update 20.01 udało się zrobić pobożemu
    # zapis w bazie danych i jej pełna eksploatacja
    @marshal_with(resource_fields)
    def get(self, num):
        args = databaseModel.query.filter_by(id=num).first()
        if not args:
            abort(404, message='Nie ma takiego rekordu w bazie danych')
        return args, 201

    # url_check = [{'id': 1, 'url': 'www', 'status_code': '200', 'dataTime': '23:22:34', 'error': 'noWAY'}]
    @marshal_with(resource_fields)
    def put(self, num):
        args = http_put_status_code.parse_args()
        result = databaseModel.query.filter_by(id=num).first()
        if result:
            abort(409, message='Record is taken...')
        miarka = databaseModel(id=num, url=args['url'], status_code=args['status_code'], dataTime=args['dataTime'], error=args['error'])
        db.session.add(miarka)
        db.session.commit()
        return miarka, 201

    @marshal_with(resource_fields)
    def patch(self, num):
        # patch to updata jkc
        # nie kraść kodu bo wpierdol
        args = http_put_status_code_update.parse_args()
        result = databaseModel.query.filter_by(id=num).first()

        if not result:
            api_for_hhtp.put(self, num)
            abort(404, message='Rekord nie istanieje do podmianki...')

        if args['url']:
            result.url = args['url']
        if args['status_code']:
            result.status_code = args['status_code']
        if args['dataTime']:
            result.dataTime = args['dataTime']
        if args['error']:
            result.error = args['error']

        db.session.commit()

        return result

    # def put(self, data):
    #     args = http_put_status_code.parse_args()
    #     url_check[data] = args
    #     return url_check[data], 201


class all_i_want(Resource):

    @marshal_with(resource_fields)
    def put(self, num):
        args = http_put_status_code.parse_args()
        result = alliwantALL.query.filter_by(id=num).first()
        if result:
            abort(409, message='Record is taken[sekcja z alliwant]...')
        miarka = alliwantALL(id=num, url=args['url'], status_code=args['status_code'], dataTime=args['dataTime'], error=args['error'])
        db.session.add(miarka)
        db.session.commit()
        return miarka, 201

    @marshal_with(resource_fields)
    def patch(self, num):
        # patch to updata jkc
        # nie kraść kodu bo wpierdol
        args = http_put_status_code_update.parse_args()
        result = alliwantALL.query.filter_by(id=num).first()

        if not result:
            all_i_want.put(self, num)
            abort(404, message='Rekord nie istanieje do podmianki[sekcja z alliwant]...')

        if args['url']:
            result.url = args['url']
        if args['status_code']:
            result.status_code = args['status_code']
        if args['dataTime']:
            result.dataTime = args['dataTime']
        if args['error']:
            result.error = args['error']

        db.session.commit()

        return result


class all_i_want_WRONG(Resource):
    @marshal_with(resource_fields)
    def put(self, num):
        args = http_put_status_code.parse_args()
        result = alliwantWRONG.query.filter_by(id=num).first()
        if result:
            abort(409, message='Record is taken...')
        miarka = alliwantWRONG(id=num, url=args['url'], status_code=args['status_code'], dataTime=args['dataTime'], error=args['error'])
        db.session.add(miarka)
        db.session.commit()
        return miarka, 201

    def delete(self, num):
        result = alliwantWRONG.query.filter_by(id=num).one()
        db.session.delete(result)
        db.session.commit()

api.add_resource(HelloWorld, "/toja")
api.add_resource(api2, '/aaa')
api.add_resource(api3, '/zxc/<string:name>')
api.add_resource(apiA, '/api/v1/<int:dane>')
api.add_resource(api_for_hhtp, '/v1/first/api/<int:num>')
api.add_resource(api_for_http_wrong, '/v1/twice/api/<int:num>')
api.add_resource(all_i_want, '/v2/first/api/<int:num>')
api.add_resource(all_i_want_WRONG, '/v2/twice/api/<int:num>')

if __name__ == '__main__':
    app.run(debug=True)
