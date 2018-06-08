SELECT year(e.dt) YR, month(e.dt) MO, day(e.dt) DAY, minute(e.dt) MIN, e.ip IP, ua.value UA, url.value URL
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
INNER JOIN ua ON e.id_ua = ua.id
WHERE vhost.value = 'mcm.edsuom.com'
 AND e.http != 404
 AND 12*(year(now()) - year(e.dt)) + month(now()) - month(e.dt) < 6
 AND url.value REGEXP 'crpm='
ORDER BY YR DESC, MO DESC, DAY DESC, MIN DESC;


