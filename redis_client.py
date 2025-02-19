import redis
from core.config import settings
import logging


# Initialize Redis client
redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB
)

def check_redis_connection():
    try:
        redis_client.ping()
        logging.info("Redis client is running.")
    except redis.ConnectionError:
        logging.error("Redis client is not running.")

# Call the function to check the Redis connection
check_redis_connection()