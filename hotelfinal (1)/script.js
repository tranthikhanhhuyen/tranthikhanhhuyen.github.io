

const DB = {
    currentUser: JSON.parse(localStorage.getItem('artisan_user')) || null,
    bookings: JSON.parse(localStorage.getItem('artisan_bookings')) || [],
    
    // 10 PHÒNG NGHỈ CHI TIẾT
    rooms: [
        { id: 101, name: "Grand Deluxe Garden View", type: "Deluxe", basePrice: 350, maxAdults: 2, maxChildren: 1, area: 45, img: "https://images.pexels.com/photos/164595/pexels-photo-164595.jpeg", rating: 4.8, review: "Không gian xanh mát mắt và giường ngủ cực kỳ êm ái.", reviewer: "Thanh Tùng", amenities: ["Wifi", "AC", "Minibar"] },
        { id: 102, name: "Grand Deluxe Ocean Front", type: "Deluxe", basePrice: 450, maxAdults: 2, maxChildren: 1, area: 50, img: "https://images.pexels.com/photos/271618/pexels-photo-271618.jpeg", rating: 4.9, review: "Tiếng sóng biển rì rào ngay ban công, phòng cực kỳ sạch sẽ.", reviewer: "Ngọc Lan", amenities: ["Sea View", "King Bed", "Balcony"] },
        { id: 103, name: "Terrace Garden Premium", type: "Deluxe", basePrice: 380, maxAdults: 2, maxChildren: 1, area: 48, img: "https://images.pexels.com/photos/262048/pexels-photo-262048.jpeg", rating: 4.7, review: "Sân hiên rộng rãi, thích hợp cho việc ngồi trà chiều.", reviewer: "Minh Anh", amenities: ["Garden", "Bathtub", "Smart TV"] },
        { id: 201, name: "Imperial Royal Suite", type: "Suite", basePrice: 850, maxAdults: 3, maxChildren: 2, area: 110, img: "https://images.pexels.com/photos/1579253/pexels-photo-1579253.jpeg", rating: 5.0, review: "Xứng đáng đến từng xu. Dịch vụ tận tình, nội thất sang trọng.", reviewer: "Khánh Huyền", amenities: ["Butler", "Living Room", "Jacuzzi"] },
        { id: 202, name: "Presidential Sky Suite", type: "Suite", basePrice: 1200, maxAdults: 4, maxChildren: 2, area: 150, img: "https://images.pexels.com/photos/1571460/pexels-photo-1571460.jpeg", rating: 5.0, review: "Tầm nhìn bao trọn thành phố, tiện ích thông minh ấn tượng.", reviewer: "Hoàng Gia", amenities: ["360 View", "Office", "Kitchen"] },
        { id: 203, name: "Penthouse Lakeview", type: "Suite", basePrice: 1500, maxAdults: 4, maxChildren: 2, area: 200, img: "https://images.pexels.com/photos/1457842/pexels-photo-1457842.jpeg", rating: 4.9, review: "Đẳng cấp thượng lưu, hồ bơi vô cực ngay trong phòng.", reviewer: "Bùi Trinh", amenities: ["Private Pool", "Wine Cellar"] },
        { id: 301, name: "Cliffside Azure Villa", type: "Villa", basePrice: 2500, maxAdults: 6, maxChildren: 4, area: 350, img: "https://images.pexels.com/photos/189296/pexels-photo-189296.jpeg", rating: 5.0, review: "Biệt thự biệt lập, hồ bơi riêng cực đẹp cho cả gia đình.", reviewer: "Vĩnh Thụy", amenities: ["Private Beach", "Gym", "Chef"] },
        { id: 302, name: "Sanctuary Beach Villa", type: "Villa", basePrice: 3500, maxAdults: 8, maxChildren: 4, area: 500, img: "https://images.pexels.com/photos/2467285/pexels-photo-2467285.jpeg", rating: 5.0, review: "Sự riêng tư tuyệt đối, quản gia phục vụ 24/7.", reviewer: "Duy Hoàng", amenities: ["Cinema", "Steam Room"] },
        { id: 303, name: "Modernist Forest Retreat", type: "Villa", basePrice: 2200, maxAdults: 4, maxChildren: 2, area: 180, img: "https://images.pexels.com/photos/323780/pexels-photo-323780.jpeg", rating: 4.8, review: "Kiến trúc độc bản giữa rừng thông, cực kỳ yên tĩnh.", reviewer: "Thu Trang", amenities: ["Fireplace", "Yoga Deck"] },
        { id: 304, name: "Eco-Luxury Floating Villa", type: "Villa", basePrice: 4000, maxAdults: 4, maxChildren: 2, area: 220, img: "https://images.pexels.com/photos/1268855/pexels-photo-1268855.jpeg", rating: 5.0, review: "Trải nghiệm ngủ giữa lòng hồ tuyệt diệu nhất tôi từng có.", reviewer: "Ngọc Hà", amenities: ["Underwater View", "Solar Power"] }
    ],

    menu: [
        { id: 1, name: "Sò Điệp Hokkaido Áp Chảo", price: 120, category: "Appetizer", desc: "Sốt bơ chanh béo ngậy và trứng cá tầm muối thượng hạng.", img: "https://images.pexels.com/photos/2092906/pexels-photo-2092906.jpeg" },
        { id: 2, name: "Bò Wagyu A5 Gold Leaf", price: 550, category: "Main", desc: "Thịt bò dát vàng 24K, ăn kèm nấm Truffle đen từ Pháp.", img: "https://images.pexels.com/photos/675951/pexels-photo-675951.jpeg" },
        { id: 3, name: "Tôm Hùm Xanh Bỏ Lò", price: 280, category: "Main", desc: "Tôm hùm đại dương phục vụ cùng sốt kem phô mai Gruyère.", img: "https://images.pexels.com/photos/699953/pexels-photo-699953.jpeg" },
        { id: 4, name: "Gan Ngỗng Pháp Áp Chảo", price: 180, category: "Appetizer", desc: "Sốt dâu rừng chua ngọt cân bằng vị béo của gan ngỗng.", img: "https://images.pexels.com/photos/103124/pexels-photo-103124.jpeg" },
        { id: 5, name: "Súp Nấm Truffle Trắng", price: 95, category: "Soup", desc: "Hương thơm nồng nàn từ nấm rừng quý hiếm và kem tươi.", img: "https://images.pexels.com/photos/1731535/pexels-photo-1731535.jpeg" },
        { id: 6, name: "Cá Hồi King Salmon", price: 150, category: "Main", desc: "Cá hồi New Zealand áp chảo mặt da giòn tan, sốt miso.", img: "https://images.pexels.com/photos/46239/salmon-dish-food-meal-46239.jpeg" },
        { id: 7, name: "Mì Ý Tôm Hùm Al Dente", price: 210, category: "Main", desc: "Sợi mì làm thủ công hòa quyện cùng thịt tôm hùm tươi rói.", img: "https://images.pexels.com/photos/691114/pexels-photo-691114.jpeg" },
        { id: 8, name: "Tráng Miệng Socola Lava", price: 65, category: "Dessert", desc: "Socola nguyên chất tan chảy bên trong lớp vỏ bánh mềm.", img: "https://images.pexels.com/photos/2144112/pexels-photo-2144112.jpeg" },
        { id: 9, name: "Salad Cầu Vồng Nhiệt Đới", price: 55, category: "Healthy", desc: "Rau củ hữu cơ và sốt hạt thông béo bùi, tốt cho sức khỏe.", img: "https://images.pexels.com/photos/1059943/pexels-photo-1059943.jpeg" },
        { id: 10, name: "Rượu Vang Chateau Margaux", price: 1200, category: "Wine", desc: "Dòng vang đỏ huyền thoại niên đại 2015 dành cho giới thượng lưu.", img: "https://images.pexels.com/photos/290316/pexels-photo-290316.jpeg" }
    ],

    spa: [
        { id: 1, name: "Tái Tạo Năng Lượng Thụy Điển", time: "90 Phút", price: 200, desc: "Massage toàn thân chuyên sâu giảm căng cơ và stress." },
        { id: 2, name: "Tẩy Tế Bào Chết Vàng 24K", time: "60 Phút", price: 350, desc: "Liệu pháp xa xỉ giúp làm sáng và trẻ hóa làn da tức thì." },
        { id: 3, name: "Ngâm Mình Trong Thảo Dược", time: "45 Phút", price: 120, desc: "Hương thơm từ hoa cỏ thiên nhiên giúp thư giãn tinh thần." },
        { id: 4, name: "Massage Đá Nóng Núi Lửa", time: "90 Phút", price: 220, desc: "Năng lượng từ đá nóng giúp lưu thông khí huyết hiệu quả." },
        { id: 5, name: "Liệu Pháp Trắng Sáng Trân Châu", time: "75 Phút", price: 280, desc: "Dưỡng chất từ bột ngọc trai giúp da mịn màng như lụa." },
        { id: 6, name: "Xông Hơi Tinh Dầu Bạc Hà", time: "30 Phút", price: 80, desc: "Thông thoáng lỗ chân lông và làm sạch hệ hô hấp." },
        { id: 7, name: "Bấm Huyệt Chân Thư Giãn", time: "60 Phút", price: 100, desc: "Giảm mệt mỏi sau một ngày dài di chuyển tham quan." },
        { id: 8, name: "Đắp Mặt Nạ Tảo Biển Tươi", time: "45 Phút", price: 150, desc: "Cấp ẩm sâu từ tinh túy đại dương cho làn da rạng rỡ." },
        { id: 9, name: "Trị Liệu Yoga Thân Tâm", time: "120 Phút", price: 400, desc: "Sự kết hợp hoàn hảo giữa Spa và các tư thế Yoga tĩnh tâm." },
        { id: 10, name: "Gói 'The Artisan Queen'", time: "240 Phút", price: 800, desc: "Gói chăm sóc toàn diện từ tóc đến móng chân cho quý cô." }
    ],

    gallery: [
        { url: "https://images.pexels.com/photos/258154/pexels-photo-258154.jpeg", title: "Lobby Grandeur" },
        { url: "https://images.pexels.com/photos/1134176/pexels-photo-1134176.jpeg", title: "Infinity Pool" },
        { url: "https://images.pexels.com/photos/261102/pexels-photo-261102.jpeg", title: "Dining Hall" },
        { url: "https://images.pexels.com/photos/1838554/pexels-photo-1838554.jpeg", title: "Spa Suite" },
        { url: "https://images.pexels.com/photos/221457/pexels-photo-221457.jpeg", title: "Sunset Deck" },
        { url: "https://images.pexels.com/photos/189296/pexels-photo-189296.jpeg", title: "Azure Villa" },
        { url: "https://images.pexels.com/photos/2373201/pexels-photo-2373201.jpeg", title: "Morning Mist" },
        { url: "https://images.pexels.com/photos/338504/pexels-photo-338504.jpeg", title: "Night View" },
        { url: "https://images.pexels.com/photos/271643/pexels-photo-271643.jpeg", title: "Master Bed" },
        { url: "https://images.pexels.com/photos/70441/pexels-photo-70441.jpeg", title: "Gourmet Platters" }
    ]
};

const app = {
    state: {
        page: 'home',
        adults: 2,
        children: 0,
        checkIn: new Date().toISOString().split('T')[0],
        checkOut: new Date(Date.now() + 86400000).toISOString().split('T')[0],
        pendingBooking: null,
        payMethod: 'momo',
        userPhone: null
    },

    init: function() {
        this.navigate('home');
        this.bindEvents();
        this.updateAuthUI();
    },

    bindEvents: function() {
        window.addEventListener('scroll', () => {
            const nav = document.getElementById('navbar');
            if (window.scrollY > 80) nav.classList.add('scrolled');
            else nav.classList.remove('scrolled');
        });
    },

    navigate: function(page) {
        this.state.page = page;
        window.scrollTo({ top: 0, behavior: 'smooth' });
        this.render();
    },

    calculateNights: function() {
        const d1 = new Date(this.state.checkIn);
        const d2 = new Date(this.state.checkOut);
        const diffTime = Math.abs(d2 - d1);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        return diffDays > 0 ? diffDays : 1;
    },

    calculateFinalPrice: function(base) {
        const nights = this.calculateNights();
        let total = base * nights;
        if (this.state.adults > 2) total += (base * 0.35 * (this.state.adults - 2)) * nights;
        total += (base * 0.20 * this.state.children) * nights;
        return Math.round(total);
    },

    updateState: function(key, val) {
        this.state[key] = val;
        if (key === 'checkIn' || key === 'checkOut' || key === 'adults' || key === 'children') {
            this.render();
        }
    },

    render: function() {
        const main = document.getElementById('main-content');
        if (!main) return;

        switch(this.state.page) {
            case 'home': main.innerHTML = this.tplHome(); break;
            case 'rooms': main.innerHTML = this.tplRooms(); break;
            case 'dining': main.innerHTML = this.tplDining(); break;
            case 'gallery': main.innerHTML = this.tplGallery(); break;
        }
        this.initAnimations();
    },

    initAnimations: function() {
        const reveals = document.querySelectorAll('.reveal');
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if(entry.isIntersecting) entry.target.classList.add('active');
            });
        }, { threshold: 0.1 });
        reveals.forEach(el => observer.observe(el));
    },

    updateAuthUI: function() {
        const userDisplay = document.getElementById('user-display-name');
        if (DB.currentUser) {
            userDisplay.innerText = DB.currentUser.name;
        } else {
            userDisplay.innerText = "Login";
        }
    },

    tplHome: function() {
        return `
            <header class="hero reveal">
                <div class="hero-content">
                    <span class="hero-subtitle">The Pinnacle of Luxury Reimagined</span>
                    <h1 class="hero-title">Experience Timeless<br>Elegance</h1>

                    <div class="hero-btns" style="margin-top:30px">
                        <button class="btn-primary" onclick="app.navigate('rooms')">Book Your Stay</button>
                        <button class="btn-outline" onclick="app.navigate('dining')">Michelin Dining</button>
                    </div>
                </div>
            </header>
            <section class="section-padding">
                <div class="section-header"><span>Core Values</span><h2>Why The Artisan?</h2></div>
                <div class="services-grid">
                    <div class="service-item reveal">
                        <i class="fas fa-microchip service-icon"></i>
                        <h3>AI Automation</h3>
                        <p>Automated booking system optimizing rates in real-time for guests.</p>
                    </div>
                    <div class="service-item reveal">
                        <i class="fas fa-shield-alt service-icon"></i>
                        <h3>Privacy First</h3>
                        <p>Securing customer data according to ISO 27001 standards.</p>
                    </div>
                    <div class="service-item reveal">
                        <i class="fas fa-leaf service-icon"></i>
                        <h3>Eco-Luxury</h3>
                        <p>Combining luxury with sustainable environmental protection.</p>
                    </div>
                </div>
            </section>
        `;
    },

    tplRooms: function() {
        let roomsHtml = DB.rooms.map(room => {
            if (this.state.adults > room.maxAdults) return '';
            const totalPrice = this.calculateFinalPrice(room.basePrice);
            return `
                <div class="room-card reveal">
                    <div class="room-img-wrapper">
                        <img src="${room.img}" class="room-img" alt="${room.name}">
                        <div class="area-overlay" style="position:absolute; top:20px; left:20px; background:rgba(0,0,0,0.5); color:white; padding:5px 12px; border-radius:4px; font-size:0.8rem">${room.area} m²</div>
                        <div class="price-tag">$${room.basePrice.toLocaleString()} <span>/ Night</span></div>
                    </div>
                    <div class="room-info">
                        <div class="room-header-row" style="display:flex; justify-content:space-between; align-items:center">
                            <span class="room-category">${room.type}</span>
                            <div class="room-rating"><i class="fas fa-star" style="color:var(--primary-gold)"></i> ${room.rating}</div>
                        </div>
                        <h3 class="room-title">${room.name}</h3>
                        <div class="room-review-box">
                            <i class="fas fa-quote-left" style="color:var(--primary-gold); margin-right:10px"></i>
                            <p>${room.review}</p>
                            <span class="reviewer-name">- ${room.reviewer}</span>
                        </div>
                        <div class="room-amenities-strip">
                            ${room.amenities.map(a => `<span><i class="fas fa-check"></i> ${a}</span>`).join('')}
                        </div>
                        <button class="btn-book-room" onclick="app.handleBookingStep(${room.id}, ${totalPrice})">Confirm Selection</button>
                    </div>
                </div>
            `;
        }).join('');

        return `
            <section class="section-padding">
                <div class="section-header"><span>Accommodations</span><h2>Rooms & Suites</h2></div>
                
                <div class="booking-engine reveal">
                    <div class="engine-grid">
                        <div class="engine-item">
                            <label><i class="fas fa-calendar-alt"></i> Check In</label>
                            <input type="date" value="${this.state.checkIn}" onchange="app.updateState('checkIn', this.value)">
                        </div>
                        <div class="engine-item">
                            <label><i class="fas fa-calendar-day"></i> Check Out</label>
                            <input type="date" value="${this.state.checkOut}" onchange="app.updateState('checkOut', this.value)">
                        </div>
                        <div class="engine-item">
                            <label><i class="fas fa-user-friends"></i> Adults</label>
                            <select onchange="app.updateState('adults', parseInt(this.value))">
                                <option value="1" ${this.state.adults==1?'selected':''}>1 Guest</option>
                                <option value="2" ${this.state.adults==2?'selected':''}>2 Guests</option>
                                <option value="4" ${this.state.adults==4?'selected':''}>4 Guests</option>
                            </select>
                        </div>
                        <div class="engine-item">
                            <label><i class="fas fa-child"></i> Children</label>
                            <select onchange="app.updateState('children', parseInt(this.value))">
                                <option value="0" ${this.state.children==0?'selected':''}>No Children</option>
                                <option value="1" ${this.state.children==1?'selected':''}>1 Child</option>
                                <option value="2" ${this.state.children==2?'selected':''}>2 Children</option>
                            </select>
                        </div>
                        <button class="btn-search" onclick="app.navigate('rooms')">Check Rates</button>
                    </div>
                </div>

                <div class="room-grid">${roomsHtml}</div>
            </section>
        `;
    },

    tplDining: function() {
        const menuHtml = DB.menu.map(item => `
            <div class="room-card reveal">
                <img src="${item.img}" class="room-img" style="height:200px; width:100%; object-fit:cover">
                <div class="room-info">
                    <span class="room-category">${item.category}</span>
                    <h4 style="margin:10px 0">${item.name}</h4>
                    <p style="font-size:0.8rem; color:gray; height:40px">${item.desc}</p>
                    <p style="color:var(--primary-gold); font-weight:bold; margin-top:10px; font-size:1.2rem">$${item.price}</p>
                </div>
            </div>
        `).join('');

        return `
            <section class="section-padding">
                <div class="section-header"><span>The Artisan Dining</span><h2>Michelin Star Menu</h2></div>
                <div class="room-grid" style="display:grid; grid-template-columns:repeat(auto-fill, minmax(280px, 1fr)); gap:30px">${menuHtml}</div>
            </section>
        `;
    },

    tplGallery: function() {
        const items = DB.gallery.map(img => `
            <div class="reveal" style="position:relative; overflow:hidden; border-radius:10px; aspect-ratio:1/1">
                <img src="${img.url}" class="room-img" style="display:block; transition: 0.8s; height:100%; width:100%; object-fit:cover">
                <div style="position:absolute; bottom:0; left:0; width:100%; padding:20px; background:linear-gradient(transparent, rgba(15,23,42,0.9)); color:white">
                    <h4 style="font-size:1rem">${img.title}</h4>
                </div>
            </div>
        `).join('');
        return `
            <section class="section-padding">
                <div class="section-header"><span>Visual Experience</span><h2>Hotel Gallery</h2></div>
                <div class="room-grid" style="display:grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap:20px">${items}</div>
            </section>
        `;
    },

    // --- ENHANCED BOOKING FLOW ---
    handleBookingStep: async function(id, price) {
        if (!DB.currentUser) {
            Swal.fire('Identity Verification', 'Please log in to continue your booking.', 'info');
            auth.open();
            return;
        }

        // STEP 1: Phone Verification (Requirement: MUST prompt for phone)
        const { value: phone } = await Swal.fire({
            title: 'Contact Verification',
            input: 'tel',
            inputLabel: 'Please enter your phone number to receive booking updates',
            inputPlaceholder: '+84 ...',
            showCancelButton: true,
            confirmButtonColor: '#c5a059',
            inputValidator: (value) => {
                if (!value) return 'We need your phone number for reservation security!';
                if (value.length < 8) return 'Please enter a valid phone number.';
            }
        });

        if (phone) {
            this.state.userPhone = phone;
            this.processBooking(id, price);
        }
    },

    processBooking: function(id, price) {
        const room = DB.rooms.find(r => r.id === id);
        const nights = this.calculateNights();
        
        this.state.pendingBooking = { 
            room: room.name, 
            price: room.basePrice,
            total: price, 
            checkIn: this.state.checkIn,
            checkOut: this.state.checkOut,
            nights: nights,
            img: room.img
        };
        
        // Update Modal UI
        document.getElementById('pay-room-name').innerText = room.name;
        document.getElementById('pay-room-img').src = room.img;
        document.getElementById('pay-amount').innerText = '$' + room.basePrice.toLocaleString();
        document.getElementById('pay-nights-val').innerText = `${nights} Night${nights > 1 ? 's' : ''}`;
        document.getElementById('pay-total').innerText = '$' + price.toLocaleString();
        document.getElementById('pay-checkin').innerText = this.state.checkIn;
        document.getElementById('pay-checkout').innerText = this.state.checkOut;
        document.getElementById('pay-nights').innerText = nights + " Night" + (nights > 1 ? "s" : "");
        document.getElementById('user-phone').innerText = this.state.userPhone;
        
        document.getElementById('paymentModal').style.display = 'flex';
    },

    closePayment: function() {
        document.getElementById('paymentModal').style.display = 'none';
    },

    setPayMethodV2: function(method) {
        this.state.payMethod = method;
    },

    confirmPayment: function() {
        Swal.fire({
            title: 'Processing Transaction',
            html: `Establishing secure connection to <b>${this.state.payMethod.toUpperCase()}</b> Gateway...`,
            timer: 2000,
            didOpen: () => Swal.showLoading()
        }).then(() => {
            Swal.fire({
                title: 'Reservation Secured!',
                text: `Thank you ${DB.currentUser.name}, your stay at ${this.state.pendingBooking.room} is confirmed. A summary has been sent to ${this.state.userPhone}.`,
                icon: 'success',
                confirmButtonColor: '#c5a059'
            });
            this.closePayment();
        });
    }
};

const auth = {
    isLogin: true,
    open: () => {
        document.getElementById('authModal').style.display = 'flex';
        document.body.style.overflow = 'hidden';
    },
    close: () => {
        document.getElementById('authModal').style.display = 'none';
        document.body.style.overflow = 'auto';
    },
    toggle: function() {
        this.isLogin = !this.isLogin;
        document.getElementById('authTitle').innerText = this.isLogin ? "Welcome Back" : "Create Account";
        document.getElementById('authSubtitle').innerText = this.isLogin ? "Please enter your details to continue" : "Join our luxury membership today";
    },
    submit: function() {
        const user = document.getElementById('authUser').value;
        if (!user) return Swal.fire('Error', 'Username is required.', 'error');
        DB.currentUser = { name: user.split('@')[0], email: user };
        localStorage.setItem('artisan_user', JSON.stringify(DB.currentUser));
        app.updateAuthUI();
        this.close();
        Swal.fire('Welcome', `Glad to have you back, ${DB.currentUser.name}!`, 'success');
    }
};

document.addEventListener('DOMContentLoaded', () => app.init());