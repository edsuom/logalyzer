/* Select a URL that everyone will fetch. (I use the contact email PNG.)
   Prepare to see lots of logspam. You can weed it out by updating logspam.ref
   or adding your own .ref file(s).
*/
SELECT year(e.dt) YR, month(e.dt) MO, day(e.dt) DAY, e.ip IP, ref.value REFERRER
FROM entries e
INNER JOIN ref ON e.id_ref = ref.id
INNER JOIN url ON e.id_url = url.id
WHERE e.http != 404
 AND year(e.dt) = year(now())
 AND month(e.dt) = month(now())
 AND url.value = '/pics/contact.png'
ORDER BY YR DESC, MO DESC, DAY DESC
LIMIT 1000;



