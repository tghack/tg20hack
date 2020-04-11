FROM nginx:latest

COPY server/default /etc/nginx/conf.d/default.conf
COPY src/build /var/www/html/

CMD service nginx start && /bin/bash
