import json
import boto3
import os
import urllib
from pymongo import MongoClient, errors
from bson import ObjectId
from botocore.exceptions import ClientError
import urllib3
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor

# Initialize OpenTelemetry Tracer
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)
trace.get_tracer_provider().add_span_processor(
    SimpleSpanProcessor(ConsoleSpanExporter())
)

URLLib3Instrumentor().instrument()

def lambda_handler(event, context):
    print('Received event:', event)
    print('Context:', context)

    # Check if the SecretString field is not undefined before trying to parse it as JSON
    mongo_db_uri = get_mongo_db_uri()

    if not mongo_db_uri:
        print('Failed to retrieve MongoDB URI from secret store')
        return {
            'statusCode': 500,
            'body': 'Internal server error - Failed to retrieve MongoDB URI from secret store',
        }

    method = event['httpMethod']
    print('HTTP Method:', method)

    client = MongoClient(mongo_db_uri, tlsCAFile='global-bundle.pem')

    try:
        with client:
            db = client.mydb
            collection = db.mycollection

            print('Connected to MongoDB')
            playground_response = call_3rdPartyEndpoint()
            if playground_response is None:
                return {
                    'statusCode': 500,
                    'body': 'Internal server error - Failed to call playgroundtech.io'
                }
            if method == 'GET':
                return handle_get_request(collection)
            elif method == 'POST':
                return handle_post_request(event, collection)
            elif method == 'PUT':
                return handle_put_request(event, collection)
            elif method == 'DELETE':
                return handle_delete_request(event, collection)
            else:
                return handle_unsupported_method()
    except errors.ConnectionFailure as e:
        print('MongoDB connection error:', e)
        return {
            'statusCode': 500,
            'body': 'Internal server error - MongoDB connection error',
        }
# Custom encoder to handle ObjectId serialization
class MongoEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return super().default(o)


def handle_get_request(collection):
    data = list(collection.find())
    print('Fetched data:', data)
    serialized_data = json.dumps(data, cls=MongoEncoder, indent=2)

    return {
        'statusCode': 200,
        'body': serialized_data,
    }

def handle_post_request(event, collection):
    payload = json.loads(event['body'] or '{}')
    print('Received payload:', payload)
    result = collection.insert_one(payload)
    print('Inserted data:', result.inserted_id)
    return {
        'statusCode': 201,
        'body': json.dumps(str(result.inserted_id)),
    }

def handle_put_request(event, collection):
    updated_payload = json.loads(event['body'] or '{}')
    print('Updated payload:', updated_payload)

    filter = {'_id': ObjectId(updated_payload['_id'])}
    del updated_payload['_id']  # The _id cannot be updated

    result = collection.update_one(filter, {'$set': updated_payload})
    print('Updated data:', result.modified_count)

    return {
        'statusCode': 200,
        'body': json.dumps(result.modified_count),
    }

def handle_delete_request(event, collection):
    id_to_delete = event['queryStringParameters']['id']

    try:
        filter = {'_id': ObjectId(id_to_delete)}
        result = collection.delete_one(filter)
        print('Deleted data:', result.deleted_count)

        return {
            'statusCode': 200,
            'body': json.dumps(result.deleted_count),
        }
    except errors.OperationFailure as e:
        print('Error deleting document:', e)
        return {
            'statusCode': 500,
            'body': 'Internal server error - Failed to delete document',
        }

def handle_unsupported_method():
    print('Unsupported HTTP method')
    return {
        'statusCode': 400,
        'body': 'Unsupported HTTP method',
    }

# Get MongoDB URI from AWS Secret Manager
def get_mongo_db_uri():
    try:
        secret_name = os.environ['DOCUMENTDB_SECRET_NAME']
        print('secret_name:', secret_name)
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId=secret_name, VersionStage="AWSCURRENT")
        print('response:', response)
        if 'SecretString' in response:
            secret = json.loads(response['SecretString'])
            host = secret.get('host', 'DOCDBURL')
            password = urllib.parse.quote_plus(secret.get('master_password', 'DOCPASSWORD'))
            username = secret.get('master_username', 'myuser')
            port = secret.get('port', '27017')

            uri = f'mongodb://{username}:{password}@{host}:{port}/aritrademodatabase?tls=true&tlsCAFile=global-bundle.pem&replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false'
            print('uri:', uri)

            return uri
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        print('Client Error', e)
    except Exception as e:
        print('Error retrieving MongoDB URI:', e)
    return None


def call_3rdPartyEndpoint():
    with tracer.start_as_current_span("call_3rdPartyEndpoint"):
        url = "https://postman-echo.com/get?test=123"
        request = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(request) as response:
                response_body = response.read()
                print("Response from Endpoint:", response_body)
                return json.loads(response_body)
        except urllib.error.URLError as e:
            print("Error calling Endpoint:", e)
            return None
        except Exception as e:
            print("Error calling Endpoint:", e)
            return None
