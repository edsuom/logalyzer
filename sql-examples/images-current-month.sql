SELECT year(e.dt) YR, month(e.dt) MO, day(e.dt) DAY, count(distinct(e.ip)) N, url.value URL
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE vhost.value REGEXP '(www\.)?edsuom.com'
 AND e.http != 404
 AND 12*(year(now()) - year(e.dt)) + month(now()) - month(e.dt) < 2
 AND url.value REGEXP '/pics/.+\.(jpg|png)$'
GROUP BY YR, MO, DAY, URL
ORDER BY YR DESC, MO DESC, DAY DESC, N DESC;


