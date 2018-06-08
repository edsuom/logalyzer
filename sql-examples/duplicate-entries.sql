select *
from entries e1 inner join entries e2
on e1.id != e2.id and
e1.dt = e2.dt and
e1.ip = e2.ip and
e1.http = e2.http and
e1.was_rd = e2.was_rd and
e1.id_vhost = e2.id_vhost and
e1.id_url = e2.id_url and
e1.id_ref = e2.id_ref and
e1.id_ua = e2.id_ua;

