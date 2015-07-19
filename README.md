## **Zest Web Framework**

Zest is a lightweight WSGI web framework of Python.

#### Asynchronous server
Zest implements an asynchronous server base on asyncio, it can easily solve the C10K problem and have a high-performance.


## **Hello, World**

    from zest.web import App

    app = App()

    @app.get('/')
    def index(request):
        return 'Hello, World!'

    if __name__ == "__main__":
        app.run()

Run this script and go to http://localhost:7676. You will see the world.

## **NOTE**

Zest is considered alpha quality now, So:

**Do not use in production for now!**

## **Document**
You can find reference documentation [here][doc](TODO)

[doc]:http:pyzest.com/tutorial
