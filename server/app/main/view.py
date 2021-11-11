from . import main


@main.route("/", methods=["GET"])
def index():
    return "Testing server"
