import yaml, json
import os
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, Response
from jsonformatter import JsonFormatter
import logging
from xsdata.formats.dataclass.context import XmlContext
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig
import xml.etree.ElementTree as ET

app = Flask(__name__)


def setup_logging():
    log_handler = RotatingFileHandler(
        "/opt/synapse/logs/log.log", maxBytes=1000000, backupCount=3
    )
    formatter = JsonFormatter(
        {
            "level": "levelname",
            "timestamp": "asctime",
            "msg": "message",
            "URL": "URL",
            "method": "method",
            "remoteAddr": "remoteAddr",
            "status": "status",
            "traceid": "traceid",
        }
    )
    log_handler.setFormatter(formatter)
    log_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    app.logger.addHandler(log_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)


def log_error(e, status):
    app.logger.error(
        str(e),
        extra={
            "URL": request.path,
            "method": request.method,
            "remoteAddr": request.remote_addr,
            "status": str(status),
            "traceid": request.headers.get("x-b3-traceId", "none"),
        },
    )


def log_info(message, status):
    app.logger.info(
        message,
        extra={
            "URL": request.path,
            "method": request.method,
            "remoteAddr": request.remote_addr,
            "status": str(status),
            "traceid": request.headers.get("x-b3-traceId", "none"),
        },
    )


def detect_data_type(data):
    try:
        json.loads(data)
        return "json"
    except ValueError:
        pass
    try:
        yaml.safe_load(data)
        return "yaml"
    except ValueError:
        pass
    try:
        ET.fromstring(data)
        return "xml"
    except ET.ParseError:
        raise ValueError("Data cannot be processed as JSON, YAML or XML")


def get_spec(config):
    spec = config["spec"]
    data_type = config["type"]
    if data_type == "yaml":
        return yaml.safe_load(spec)
    elif data_type == "json":
        return json.loads(spec)
    elif data_type == "xml":
        return ET.fromstring(spec)


def load_config():
    CONFIG_MESSAGE = os.getenv("CONFIG_MESSAGE")
    CONFIG_SPEC = os.getenv("CONFIG_SPEC")

    if CONFIG_MESSAGE:
        print("Loaded message from configmap")
        return {"message": CONFIG_MESSAGE}
    elif CONFIG_SPEC:
        data_type = detect_data_type(CONFIG_SPEC)
        print("Loaded spec from configmap")

        return {"type": data_type, "spec": CONFIG_SPEC}
    else:
        raise ValueError(
            "Neither CONFIG_MESSAGE nor CONFIG_SPEC environment variables are set"
        )


def exec_script(data, response):
    SCRIPT = os.getenv("SCRIPT")
    if SCRIPT:
        exec(SCRIPT)


def resolve_ref(schema, ref):
    parts = ref.split("/")
    current = schema
    for part in parts:
        if part == "#":
            continue
        elif part in current:
            current = current[part]
        else:
            raise KeyError(f"Invalid reference: {ref}")
    return current


def generate_example_from_schema(schema, refs={}):
    example = {}
    for prop, details in schema["properties"].items():
        if "$ref" in details:
            ref = details["$ref"]
            if ref not in refs:
                refs[ref] = resolve_ref(schema, ref)
            example[prop] = generate_example_from_schema(refs[ref], refs)
        elif "example" in details:
            example[prop] = details["example"]
        elif "default" in details:
            example[prop] = details["default"]
        elif details["type"] == "object":
            example[prop] = generate_example_from_schema(details, refs)
        elif details["type"] == "array":
            example[prop] = [generate_example_from_schema(details["items"], refs)]
        else:
            example[prop] = f"Example {details['type']}"
    return example


def generate_response_from_openapi(spec, endpoint, method):
    response = spec["paths"][endpoint][method]["responses"]["200"]
    content_type = "application/json"
    if "content" in response and content_type in response["content"]:
        media_type = response["content"][content_type]
        if "schema" in media_type:
            schema = media_type["schema"]
            if "$ref" in schema:
                ref = schema["$ref"]
                schema = resolve_ref(spec, ref)
            return generate_example_from_schema(schema)
    raise ValueError("Response schema not found")


def generate_response_from_xsd(spec):
    config = ParserConfig(fail_on_unknown_properties=False)
    context = XmlContext()
    parser = XmlParser(context=context, config=config)
    schema = parser.from_string(spec)
    return schema


def generate_response_from_wsdl(client, service_name, operation_name):
    service = client.service[service_name]
    operation = service[operation_name]
    return operation._binding.input.body.parts[0].element(signature=True)


def handle_request(data, endpoint, config):
    log_info("Received request", "received")

    if "message" in config:
        response = json.loads(config["message"])
        try:
            exec_script(data, response)
        except Exception as e:
            log_error(e, 500)
            return jsonify({"error": str(e)}), 500

        log_info("Sending response", 200)
        return jsonify(response), 200

    elif "spec" in config:
        spec = get_spec(config)

        if "openapi" in spec:
            response = generate_response_from_openapi(
                spec, endpoint, request.method.lower()
            )
            try:
                exec_script(data, response)
            except Exception as e:
                log_error(e, 500)
                return jsonify({"error": str(e)}), 500
            log_info("Sending response", 200)
            return jsonify(response), 200

        elif "xsd" in spec:
            response = generate_response_from_xsd(spec, "ResponseElement")
            try:
                exec_script(data, response)
            except Exception as e:
                log_error(e, 500)
                return jsonify({"error": str(e)}), 500
            log_info("Sending response", 200)
            return Response(response, mimetype="application/xml")

        elif "wsdl" in spec:
            client = generate_response_from_wsdl(spec, "ServiceName", "OperationName")
            try:
                exec_script(data, response)
            except Exception as e:
                log_error(e, 500)
                return jsonify({"error": str(e)}), 500
            log_info("Sending response", 200)
            return jsonify(client), 200

    log_error("No specification provided", 400)
    return jsonify({"error": "No specification provided"}), 400


# Ручки (endpoint'ы) из спецификации
@app.route("/", methods=["GET"])
def get_endpoints():
    try:
        config = load_config()
        if "spec" in config:
            spec = get_spec(config)
            endpoints = []
            if "openapi" in spec:
                for path, methods in spec["paths"].items():
                    for method in methods.keys():
                        endpoints.append((path, method[0]))
            log_info("Sending response", 200)
            return jsonify(endpoints), 200
        else:
            log_error("No specification provided", 400)
            return jsonify({"error": "No specification provided"}), 400
    except Exception as e:
        log_error(e, 500)
        return jsonify({"error": str(e)}), 500


# Создание endpoint'а без спецификации
def create_endpoint_for_message(app, config):
    path = os.getenv("URL_PATH", "/api")
    method = os.getenv("METHOD", "POST")

    def handler():
        return handle_request(request.json, path, config)

    app.add_url_rule(path, "default", handler, methods=[method.upper()])
    print(f"Created endpoint: {path} ({method.upper()})")


# Динамическое создание endpoint'ов на основе спецификации
def create_endpoints_from_spec(app, config):
    spec = get_spec(config)
    if "openapi" in spec:
        for path, methods in spec["paths"].items():
            for method in methods.items():

                def handler():
                    return handle_request(request.json, path, config)

                app.add_url_rule(path, path, handler, methods=[method[0].upper()])
                print(f"Created endpoint: {path} ({method[0].upper()})")
    else:
        create_endpoint_for_message(app, config)


def initialize_app():
    try:
        config = load_config()
        if "spec" in config:
            create_endpoints_from_spec(app, config)
        else:
            create_endpoint_for_message(app, config)
    except Exception as e:
        app.logger.error(str(e))
        raise e


setup_logging()
initialize_app()

if __name__ == "__main__":
    app.run(debug=True)
