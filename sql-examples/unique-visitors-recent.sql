SELECT year(e.dt) YR, month(e.dt) MO, count(distinct e.id_url) N, e.ip IP
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE vhost.value REGEXP '^(www\.)?edsuom\.com'
 AND e.http != 404
 AND url.value NOT REGEXP '\.(jpg|png|gif|ico|css)'
GROUP BY IP, YR, MO
HAVING N > 1
ORDER BY YR DESC, MO DESC, N DESC;


