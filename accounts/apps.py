from django.apps import AppConfig
import threading
import logging

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'  # Replace with your actual app name

    def ready(self):
        # Import inside ready to avoid circular imports
        from .views import start_consumer_thread

        def run_consumer():
            try:
                print("[DEBUG] Starting RabbitMQ consumer thread...")
                start_consumer_thread()
            except Exception as e:
                print(f"[ERROR] Failed to start RabbitMQ consumer thread: {e}")

        consumer_thread = threading.Thread(target=run_consumer, daemon=True)
        consumer_thread.start()
