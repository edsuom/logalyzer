SELECT count(distinct e.id_url) N, e.ip IP
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE e.http != 404
 AND url.value NOT REGEXP '\.(jpg|png|gif|ico|css)'
 AND datediff(now(), e.dt) < 300
GROUP BY IP
HAVING N > 10
ORDER BY N DESC;


