from fastapi.templating import Jinja2Templates
from app.web.flash import get_flashed_messages

templates = Jinja2Templates(directory="app/web/templates")
templates.env.globals["get_flashed_messages"] = get_flashed_messages