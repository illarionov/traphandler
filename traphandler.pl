#!/usr/bin/perl
use strict;
use warnings;
use utf8;
use Config::Any;
use Data::Dumper;
use Heap::Binary;
use MongoDB::Connection;
use NetSNMP::TrapReceiver;
use Socket;
require Exporter;

#Traphandler - обработчик trap'ов. Запускается из snmptrapd

my $VERSION="0.01";

use constant {
   LOGFILE => '/var/log/traphandler.log',
   CONFIG_FILE => '/etc/traphandler.conf',
   #CACHE_SECONDS  => 3*60,
   CACHE_SECONDS  => 0,
   DEBUG => 1
};

our %MAC_NOTIFICATION_OIDS = (
   #3550, 3526
   '.1.3.6.1.4.1.171.11.64.2.2.15.0.3'=>1,
   '.1.3.6.1.4.1.171.11.64.1.2.15.0.3'=>1,
   #3028
   '.1.3.6.1.4.1.171.11.63.6.2.20.0.2' => 1,
   #3010G
   '.1.3.6.1.4.1.171.11.63.1.2.2.100.1.0.1' => 1,
   #3200-10,,18,28,28f,26
   #    .des3200SeriesProd(113)
   #    .des3200ProdModel(1).
   #    .des3200-10(1)
   #    .swL2MgmtMIB(2)
   #    .swL2MgmtMIBTraps(20)
   #    .swL2MgmtMIBTrapPrefix(0)
   #    .swL2macNotification(2)
   '.1.3.6.1.4.1.171.11.113.1.1.2.20.0.2' => 1,
   '.1.3.6.1.4.1.171.11.113.1.2.2.20.0.2' => 1,
   '.1.3.6.1.4.1.171.11.113.1.3.2.20.0.2' => 1,
   '.1.3.6.1.4.1.171.11.113.1.4.2.20.0.2' => 1,
   '.1.3.6.1.4.1.171.11.113.1.5.2.20.0.2' => 1,

   #cisco cmnMacChangedNotification
   '.1.3.6.1.4.1.9.9.215.2.0.1' => 1,
);

our %L2_MAC_NOTIFICATION_OIDS = (
   #3550, 3526
   '.1.3.6.1.4.1.171.11.64.2.2.15.1' => 12*2,
   '.1.3.6.1.4.1.171.11.64.1.2.15.1' => 12*2,
   #3028
   '.1.3.6.1.4.1.171.11.63.6.2.20.2.1' => 10*2,
   #3010G
   '.1.3.6.1.4.1.171.11.63.1.2.2.100.1.2.1.1' => 10*2,
   #3200-10
   '.1.3.6.1.4.1.171.11.113.1.1.2.20.2.1.0' => 10*2,
   #3200-18
   '.1.3.6.1.4.1.171.11.113.1.2.2.20.2.1.0' => 10*2,
   #32-28
   '.1.3.6.1.4.1.171.11.113.1.3.2.20.2.1.0' => 10*2,
   #32-28f
   '.1.3.6.1.4.1.171.11.113.1.4.2.20.2.1.0' => 10*2,
   #3200-26 des3200SeriesProd(113)
   #        .des3200ProdModel(1).
   #        .des3200-26(5)
   #        .swL2MgmtMIB(2)
   #        .swL2MgmtMIBTraps(20)
   #        .swl2NotificationBindings(2)
   #        .swL2macNotifyInfo(1)
   '.1.3.6.1.4.1.171.11.113.1.5.2.20.2.1.0' => 10*2,

   #cisco cmnHistMacChangedMsg
   '.1.3.6.1.4.1.9.9.215.1.1.8.1.2' => 11*2
);

package FdbItem;

use base qw(Class::Accessor);

FdbItem->mk_accessors(qw(switch_ip switch_num port_num timestamp in_db mac
   action action_num vlan heap));

sub fdb_key {
   my $self = shift;
   return sprintf("%s%.48lx%lu%lu", $self->switch_ip, $self->mac,
      $self->switch_num,
      $self->port_num);

}

sub cmp {
   my ($self, $other) = @_;

   return $self->timestamp <=> $other->timestamp
}

sub desc {
   my $self = shift;
   return sprintf("%s ip %s sw %u port %u mac %.2x:%.2x:%.2x:%.2x:%.2x:%.2x %s",
      $self->timestamp,
      $self->switch_ip, $self->switch_num, $self->port_num,
      ($self->mac >> 40) & 0xff,
      ($self->mac >> 32) & 0xff,
      ($self->mac >> 24) & 0xff,
      ($self->mac >> 16) & 0xff,
      ($self->mac >> 8) & 0xff,
      $self->mac & 0xff,
      $self->action || 'unknown'
   );
}

package main;

our $cfg;
our $collection;
our $log;

our %fdb;
our $heap;


sub mac_notification {
   my ($pdu, $oids) = @_;

   our %actions = (
      1 => 'insert',
      2 => 'delete',
      3 => 'move'
   );

   my $switch_ip;

   if ($pdu->{receivedfrom} =~
      /\[((\d{1,2}|[01]\d{2}|2[0-4]\d|25[0-5])(\.(\d{1,2}|[01]\d{2}|2[0-4]\d|25[0-5])){3})\]/)
   {
      $switch_ip = $1;
   }else {
      $switch_ip = 0;
   }

   my %res;
   my $date;
   my $timestamp = time();

   eval {
      if (DEBUG) {
	 $date = `/bin/date +'%F %T'`;
	 chomp $date;
      }

      foreach my $ov (@$oids) {
	 my ($oid, $val, $type) = @$ov;

	 my $l;

	 #if (DEBUG) { print ($log $oid . "\n"); }

	 #XXX: cisco cmnHistMacChangedMsg
	 if (index($oid, '1.3.6.1.4.1.9.9.215.1.1.8.1.2') != -1) {
	    $l = 11*2;
	 }else {
	    $l = $L2_MAC_NOTIFICATION_OIDS{$oid} || next;
	 }

	 $val =~  s/[\"\s\r\n]+//gs;

	 my $idx = 0;
	 my $length = length($val);
	 while ($idx < $length) {
	    my $str = substr($val, $idx, $l);
	    $idx += $l;
	    my ($action, $mac, $switch_num, $port_num, $vlan);

	    if ($l == 12*2) {
	       next if ($str !~
		  /^([[:xdigit:]]{2})([[:xdigit:]]{12})([[:xdigit:]]{4})([[:xdigit:]]{4})[[:xdigit:]]{2}$/);
	       ($action, $mac, $switch_num, $port_num) = (hex($1), hex($2), hex($3), hex($4));
	    }elsif ($l == 10*2) {
	       next if ($str !~
		  /^([[:xdigit:]]{2})([[:xdigit:]]{12})([[:xdigit:]]{4})[[:xdigit:]]{2}$/);
	       ($action, $mac, $switch_num, $port_num) = (hex($1), hex($2), 1, hex($3));
	    }elsif ($l == 11*2) {
	       #cmnHistMacChangedMsg
	       next if ($str !~
		  /^([[:xdigit:]]{2})([[:xdigit:]]{4})([[:xdigit:]]{12})([[:xdigit:]]{4})$/);
	       ($action, $vlan, $mac, $switch_num, $port_num) = (hex($1),
		  hex($2), hex($3), 1, hex($4));
	    }

	    my $item = FdbItem->new({
		  timestamp=>$timestamp,
		  switch_ip=>unpack('N',inet_aton($switch_ip)),
		  switch_num=>$switch_num,
		  port_num=>$port_num,
		  mac=>$mac,
		  action=>$actions{$action},
		  action_num=>$action,
		  vlan => $vlan
	       }
	    );

	    if (DEBUG) {
	       printf($log "%s GET %s\n", $date, $item->desc);
	    }

	    $res{$item->fdb_key} = $item;
	 }
      }

      my @to_db;
      #Удалем устаревшие записи. Вносим в базу не внесенные
      for(;;) {
	 my $tmp = $heap->top;
	 last if (!defined($tmp)
	    ||($tmp->timestamp > $timestamp - CACHE_SECONDS));
	 $tmp = $heap->extract_top;
	 delete($fdb{$tmp->fdb_key});
	 if (!$tmp->in_db) {
	    push (@to_db, $tmp);
	 }
	 if (DEBUG) {
	    printf($log "%s PURGED: %s (to_db: %u)\n", $date, $tmp->desc, !$tmp->in_db);
	 }
      }

      #Загружаем записи трапа
      foreach my $t (values(%res)) {
	 if (defined($fdb{$t->fdb_key})) {
	    #Запись уже существует в fdb. Обновляем ее
	    $t->in_db(0);
	    $heap->delete($fdb{$t->fdb_key});
	    $heap->add($t);
	    $fdb{$t->fdb_key} = $t;
	    if (DEBUG) {
	       printf($log "%s UPDATED IN FDB (%u): %s\n", $date, scalar(keys(%fdb)), $t->desc);
	    }
	 }else {
	    #Запись не существует. Добавляем ее в БД и в fdb
	    $t->in_db(1);
	    $heap->add($t);
	    $fdb{$t->fdb_key} = $t;
	    push (@to_db, $t);
	    if (DEBUG) {
	       printf($log "%s ADDED TO FDB (%u): %s\n", $date, scalar(keys(%fdb)), $t->desc);
	    }
	 }
      }

      if (scalar(@to_db)) {
	 foreach my $rec (@to_db) {
	    my %new_rec = (
	       ts => $rec->timestamp+0,
	       act => $rec->action_num+0,
	       mac => $rec->mac+0,
	       ip => $rec->switch_ip+0,
	       prt => $rec->port_num+0,
	    );
	    $new_rec{sw} = $rec->switch_num+0 if ($rec->switch_num);
	    $new_rec{vlan} = $rec->vlan+0 if ($rec->vlan);
	    $collection->insert(\%new_rec);
	 }
     }
  }; #eval

   if ($@) {
      $date = `/bin/date +'%F %T'`;
      chomp $date;
      printf($log "%s %s\n", $date, $@);
   }

   return 1;
}

$cfg = Config::Any->load_files({files=>[(CONFIG_FILE)],
      use_ext=>1})->[0]->{(CONFIG_FILE)} || {
   connect_info => {
      host  => 'mongodb://127.0.0.1:27017',
      auto_connect => 0,
      username    => 'mongouser',
      password    => '',
      db_name     => 'mongopass'
   },
   table_mac_notifications => 'switch_fdb_log'
};

open($log, '>>', LOGFILE) or warn $!;

$heap = Heap::Binary->new();

my $dbh = MongoDB::Connection->new(%{$cfg->{connect_info}}) or die;
my $db = $dbh->get_database($cfg->{connect_info}->{db_name});
$collection = $db->get_collection($cfg->{table_mac_notifications});

foreach (keys(%MAC_NOTIFICATION_OIDS)) {
   NetSNMP::TrapReceiver::register($_, \&mac_notification) ||
      warn "failed to register our perl trap handler\n";
}

1;


