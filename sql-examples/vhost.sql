SELECT vhost.id, count(entries.id_vhost) N, vhost.value VHOST FROM entries INNER JOIN vhost on entries.id_vhost = vhost.id GROUP BY vhost.id ORDER BY N DESC;

