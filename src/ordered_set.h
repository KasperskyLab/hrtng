//-----------------
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// An ordered set of items.
#pragma once
#include <set>

#define LIST // matcher.analyze(func) in debug mode spends 148ms-146ms with vector and 147-145ms with list
#ifdef LIST
	#include <list>
#else
	#include <vector>
#endif

template<typename T, typename R>
class OrderedSet {
 private:
  typedef std::set<T, R> set_type;
  typedef typename set_type::const_iterator set_iterator;
#ifdef LIST
	//typedef std::list<set_iterator> ordering_type;
	typedef std::list<T> ordering_type;
#else
	//typedef std::vector<set_iterator> ordering_type;
	typedef std::vector<T> ordering_type;
#endif
 public:
   typedef typename ordering_type::size_type size_type;
   typedef typename ordering_type::iterator iterator;
	 typedef typename ordering_type::const_iterator const_iterator;
	 typedef typename ordering_type::const_reference const_reference;
	 static const size_type npos = static_cast<size_type>(-1);

	void clear() {
		set_.clear();
		ordering_.clear();
	}

	const_iterator begin() const { return ordering_.begin(); }
	const_iterator end()   const { return ordering_.end(); }
	const_iterator rbegin() const { return ordering_.rbegin(); }
	const_iterator rend()   const { return ordering_.rend(); }
	const_reference front() const { return ordering_.front(); }
	const_reference back() const { return ordering_.back(); }

#if 0
#ifdef LIST
	const T& operator[](size_type index) const {
		//return *ordering_[index];
		auto it = ordering_.begin();
		std::advance(it, index);
		return *it;
	}
	void remove(size_type index) {
		auto it = ordering_.begin();
		std::advance(it, index);
		set_.erase(*it);
		ordering_.erase(it);
	}
#else
	const T& operator[](size_type index) const {
		//return *ordering_[index];
		return ordering_[index];
	}
	void remove(size_type index) {
		set_.erase(ordering_[index]);
		auto it = ordering_.begin();
		std::advance(it, index);
		ordering_.erase(it);
	}
#endif
#endif

	void remove(const_iterator it) {
		set_.erase(*it);
		ordering_.erase(it);
	}

  size_type size() const {
    return ordering_.size();
  }
  bool empty() const {
    return ordering_.empty();
  }

  bool has_item(const T& t) const {
    return set_.find(t) != set_.end();
  }

  // Returns true if the item was inserted. False if it was already in the
  // set.
  bool push_back(const T& t) {
    std::pair<set_iterator, bool> result = set_.insert(t);
    if (result.second)
      ordering_.push_back(t);
    return result.second;
  }

#ifdef LIST
	bool push_front(const T& t) {
		std::pair<set_iterator, bool> result = set_.insert(t);
		if (result.second)
			ordering_.push_front(t);
		return result.second;
	}
#else
	bool push_front(const T& t) {
		std::pair<set_iterator, bool> result = set_.insert(t);
		if (result.second)
			ordering_.insert(ordering_.begin(), result.first);
		return result.second;
	}
#endif


  // Appends a range of items, skipping ones that already exist.
  template<class InputIterator>
  void append(const InputIterator& insert_begin,
              const InputIterator& insert_end) {
    for (InputIterator i = insert_begin; i != insert_end; ++i) {
      const T& t = *i;
      push_back(t);
    }
  }

#ifdef LIST
#else
	// Appends all items from the given other set.
	void append(const OrderedSet<T, R>& other) {
		for (size_type i = 0; i < other.size(); i++)
			push_back(other[i]);
	}
#endif

 private:
  set_type set_;
	ordering_type ordering_;
};
