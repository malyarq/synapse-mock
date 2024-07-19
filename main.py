import json
import os
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, Response
from jsonformatter import JsonFormatter
import logging
from openapi_schema_to_json_schema import to_json_schema
from xsdata.formats.dataclass.context import XmlContext
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig

app = Flask(__name__)
path = os.getenv("URL_PATH", "/api")
method = os.getenv("METHOD", "POST")


# Настройка логирования
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


# Загрузка данных из конфигмапы
def load_config():
    CONFIG_MESSAGE = os.getenv("CONFIG_MESSAGE")
    CONFIG_SPEC = os.getenv("CONFIG_SPEC")

    if CONFIG_MESSAGE:
        print("Loaded message from configmap")
        return {"message": CONFIG_MESSAGE}
    elif CONFIG_SPEC:
        print("Loaded spec from configmap")
        return {"spec": CONFIG_SPEC}
    else:
        raise ValueError(
            "Neither CONFIG_MESSAGE nor CONFIG_SPEC environment variables are set"
        )


# Загрузка скрипта из конфигмапы и его выполнение
def exec_script(data, response):
    SCRIPT = os.getenv("SCRIPT")
    if SCRIPT:
        try:
            exec(SCRIPT)
        except Exception as e:
            app.logger.error(
                str(e),
                extra={
                    "URL": request.path,
                    "method": request.method,
                    "remoteAddr": request.remote_addr,
                    "status": "500",
                    "traceid": request.headers.get("x-b3-traceId", "none"),
                },
            )
            return jsonify({"error": str(e)}), 500


# Генерация ответа из Json Schema
def generate_example_from_schema(schema):
    example = {}
    for prop, details in schema["properties"].items():
        if "example" in details:
            example[prop] = details["example"]
        elif "default" in details:
            example[prop] = details["default"]
        elif details["type"] == "object":
            example[prop] = generate_example_from_schema(details)
        elif details["type"] == "array":
            example[prop] = [generate_example_from_schema(details["items"])]
        else:
            example[prop] = f"Example {details['type']}"
    return example


# Генерация ответа из OpenAPI
def generate_response_from_openapi(spec, endpoint, method):
    schema = spec["paths"][endpoint][method]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    json_schema = to_json_schema(schema)
    return generate_example_from_schema(json_schema)


# Генерация ответа из XSD
def generate_response_from_xsd(spec):
    config = ParserConfig(fail_on_unknown_properties=False)
    context = XmlContext()
    parser = XmlParser(context=context, config=config)
    schema = parser.from_string(spec)
    return schema


# Генерация ответа из WSDL
def generate_response_from_wsdl(client, service_name, operation_name):
    service = client.service[service_name]
    operation = service[operation_name]
    return operation._binding.input.body.parts[0].element(signature=True)


# Функция для обработки запроса
def handle_request(data, endpoint):
    # Логирование входящего запроса
    app.logger.info(
        "Received request",
        extra={
            "URL": request.path,
            "method": request.method,
            "remoteAddr": request.remote_addr,
            "status": "received",
            "traceid": request.headers.get("x-b3-traceId", "none"),
        },
    )
    # Загрузка конфигмапы
    try:
        config = load_config()
    except ValueError as ve:
        app.logger.error(
            str(ve),
            extra={
                "URL": request.path,
                "method": request.method,
                "remoteAddr": request.remote_addr,
                "status": "500",
                "traceid": request.headers.get("x-b3-traceId", "none"),
            },
        )
        return jsonify({"error": str(ve)}), 500

    # Генерация ответа из конфигмапы
    if "message" in config:
        response = json.loads(config["message"])
        exec_script(data, response)
        return jsonify(response), 200
    elif "spec" in config:
        spec = json.loads(config["spec"])

        # Генерация ответа из OpenAPI
        if "openapi" in spec:
            response = generate_response_from_openapi(
                spec["openapi"], endpoint, request.method.lower()
            )
            exec_script(data, response)
            return jsonify(response), 200

        # Генерация ответа из XSD
        elif "xsd" in spec:
            response = generate_response_from_xsd(spec["xsd"], "ResponseElement")
            exec_script(data, response)
            return Response(response, mimetype="application/xml")

        # Генерация ответа из WSDL
        elif "wsdl" in spec:
            client = generate_response_from_wsdl(
                spec["wsdl"], "ServiceName", "OperationName"
            )
            exec_script(data, response)
            return jsonify(client), 200

    # Если спецификация не указана, вернуть ошибку
    return jsonify({"error": "No specification provided"}), 400


# Ручки (endpoint'ы) из спецификации
@app.route("/", methods=["GET"])
def get_endpoints():
    try:
        config = load_config()
        if "spec" in config:
            spec = json.loads(config["spec"])
            endpoints = []
            if "openapi" in spec:
                for path, methods in spec["openapi"]["paths"].items():
                    for method in methods.keys():
                        endpoints.append((path, method))
            return jsonify(endpoints), 200
        else:
            return jsonify({"error": "No specification provided"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Создание endpoint'а без спецификации
def create_endpoint_for_message(app):
    def handler():
        return handle_request(request.json, path)

    app.add_url_rule(path, "default", handler, methods=[method.upper()])
    print(f"Created endpoint: {path} ({method.upper()})")


# Динамическое создание endpoint'ов на основе спецификации
def create_endpoints_from_spec(app, config):
    spec = json.loads(config["spec"])
    if "openapi" in spec:
        for path, methods in spec["openapi"]["paths"].items():
            i = 0
            for method, details in methods.items():
                i += 1
                endpoint_name = details["operationId"]
                if not endpoint_name:
                    endpoint_name = f"Endpoint#{i}"

                def handler():
                    return handle_request(request.json, path)

                app.add_url_rule(path, endpoint_name, handler, methods=[method.upper()])
                print(f"Created endpoint: {path} ({method.upper()})")
    else:
        create_endpoint_for_message(app, config)


# Инициализация приложения
def initialize_app():
    try:
        config = load_config()
        if "spec" in config:
            create_endpoints_from_spec(app, config)
        else:
            create_endpoint_for_message(app)
    except Exception as e:
        app.logger.error(str(e))
        raise e


if __name__ == "__main__":
    setup_logging()
    initialize_app()
    app.run(debug=True)
