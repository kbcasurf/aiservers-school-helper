FROM postgres:15-alpine

# Copy initialization script
COPY init.sql /docker-entrypoint-initdb.d/

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB} || exit 1

# Set internal environment variables - these will be overridden by docker-compose
ENV POSTGRES_USER=aiservers
ENV POSTGRES_PASSWORD=yourpassword
ENV POSTGRES_DB=schoolhelper

EXPOSE 5432