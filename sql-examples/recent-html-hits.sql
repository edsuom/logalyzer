SELECT year(e.dt) YR, month(e.dt) MO, day(e.dt) DAY, count(distinct(e.ip)) N, vhost.value VHOST, url.value URL
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE url.value REGEXP '\.html$'
 AND e.http != 404
 AND datediff(now(), e.dt) < 180
GROUP BY YR, MO, DAY, VHOST, URL
ORDER BY YR DESC, MO DESC, DAY DESC, N DESC;


