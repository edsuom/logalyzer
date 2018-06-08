SELECT count(e.ip) N, vhost.value HOST
FROM entries e
INNER JOIN vhost ON vhost.id = e.id_vhost
WHERE vhost.value NOT REGEXP '[0-9]'
GROUP BY HOST 
ORDER BY N DESC;


