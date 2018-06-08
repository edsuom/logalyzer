SELECT year(e.dt) YR, month(e.dt) MO, day(e.dt) DAY, e.ip IP, ref.value REF
FROM entries e
INNER JOIN ref ON e.id_ref = ref.id
INNER JOIN url ON e.id_url = url.id
WHERE e.http != 404
 AND year(e.dt) = year(now())
 AND month(e.dt) = month(now())
 AND url.value = '/pics/contact.png'
 ORDER BY YR DESC, MO DESC, DAY DESC


