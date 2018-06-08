SELECT count(distinct(e.ip)) N, url.value URL
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE vhost.value REGEXP '(www\.)?tellectual.com'
 AND e.http != 404
 AND year(e.dt) = 2017
 AND month(e.dt) = 11
 AND url.value NOT REGEXP '\.(png|gif|jpg|jpeg|ico|css|woff|eot.|ttf|svg|txt)$'
GROUP BY URL
ORDER BY N DESC;


