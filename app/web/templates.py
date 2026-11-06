from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/web/templates")

# Заглушка для flash-сообщений, чтобы шаблоны не падали
templates.env.globals["get_flashed_messages"] = lambda: []