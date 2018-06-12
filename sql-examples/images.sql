SELECT year(e.dt) YR, month(e.dt) MO, count(distinct(e.ip)) N, url.value URL
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE e.http != 404
 AND url.value REGEXP '/pics/.+\.(jpg|png)$'
GROUP BY YR, MO, URL
ORDER BY YR DESC, MO DESC, N DESC
LIMIT 1000;
