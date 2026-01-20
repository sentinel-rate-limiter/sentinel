use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};


pub fn get_current_cycle_start(anchor: DateTime<Utc>, now : DateTime<Utc>) -> DateTime<Utc> {
  if anchor > now {
    return anchor;
  }
  let mut year = now.year();
  let mut month = now.month();

  let anchor_day = anchor.day();


  let this_month_aniversary = get_valid_date(year, month, anchor_day, anchor);

  if now < this_month_aniversary {
    if month == 1 {
      month = 12;
      year-=1; 
    } else {
      month-=1;
    }
    return get_valid_date(year, month, anchor_day, anchor);
  } else {
    return this_month_aniversary
  }


}


pub fn get_valid_date(year:i32, month: u32, anchor_day : u32, anchor: DateTime<Utc>) -> DateTime<Utc> {
  if let Some(date) = Utc.with_ymd_and_hms(year, month, anchor_day, anchor.hour(), anchor.minute(), anchor.second()).single() {
    return date;
  }

  let next_month_date = if month == 12 {
     Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).unwrap()
  } else {
     Utc.with_ymd_and_hms(year, month + 1, 1, 0, 0, 0).unwrap()
  };


  return next_month_date - Duration::seconds(1)
  
}