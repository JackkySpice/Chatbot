.class public Landroidx/appcompat/view/menu/kz;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final b:Landroidx/appcompat/view/menu/kz;


# instance fields
.field public final a:Ljava/util/Map;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/kz;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/kz;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/kz;->b:Landroidx/appcompat/view/menu/kz;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/kz;->a:Ljava/util/Map;

    return-void
.end method

.method public static c()Landroidx/appcompat/view/menu/kz;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/kz;->b:Landroidx/appcompat/view/menu/kz;

    return-object v0
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/l10;)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/kz;->a:Ljava/util/Map;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-interface {v0, v1, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public b(Ljava/lang/Class;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/kz;->a:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/l10;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Landroidx/appcompat/view/menu/l10;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Landroidx/appcompat/view/menu/l10;->b()V

    :cond_0
    return-void
.end method

.method public d()V
    .locals 2

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->g()Landroidx/appcompat/view/menu/uu0;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/uu0;->y()Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->g()Landroidx/appcompat/view/menu/uu0;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/uu0;->A()Z

    move-result v0

    if-eqz v0, :cond_e

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/c10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/c10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/sg0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/sg0;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/s71;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/s71;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/t10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/t10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/n30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/n30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/oy;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/oy;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/a40;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a40;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/b40;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/b40;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/s00;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/s00;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/f30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/f30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/a00;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a00;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/zz;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/zz;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/c00;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/c00;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/jg;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/jg;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/d40;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/d40;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/r30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/r30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/ip0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/ip0;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/w10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/w10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/b30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/b30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/q10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/q10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/o10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/o10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/nz;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/nz;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/p30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/p30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/b10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/b10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/qz;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/qz;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/v20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/v20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/u00;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/u00;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/j20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/j20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/v10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/v10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/q20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/q20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/u30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/u30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/i20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/i20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    invoke-static {}, Landroidx/appcompat/view/menu/q3;->g()Landroidx/appcompat/view/menu/q3;

    move-result-object v0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/z8;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/z8;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->h()Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance v0, Landroidx/appcompat/view/menu/rz;

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/rz;-><init>(Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/y30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/y30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_1
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->g()Z

    move-result v0

    if-eqz v0, :cond_2

    new-instance v0, Landroidx/appcompat/view/menu/g20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/g20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_2
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->f()Z

    move-result v0

    if-eqz v0, :cond_3

    new-instance v0, Landroidx/appcompat/view/menu/y00;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/y00;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/t20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/t20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/xz;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/xz;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_3
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->e()Z

    move-result v0

    if-eqz v0, :cond_4

    new-instance v0, Landroidx/appcompat/view/menu/l30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/l30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_4
    sget-object v0, Landroidx/appcompat/view/menu/f10;->a:Landroidx/appcompat/view/menu/co0;

    if-eqz v0, :cond_5

    new-instance v0, Landroidx/appcompat/view/menu/g10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/g10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_5
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->d()Z

    move-result v0

    if-eqz v0, :cond_6

    new-instance v0, Landroidx/appcompat/view/menu/g00;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/g00;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/d30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/d30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_6
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->c()Z

    move-result v0

    if-eqz v0, :cond_7

    new-instance v0, Landroidx/appcompat/view/menu/x00;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/x00;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/z10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/z10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/y20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_7
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->b()Z

    move-result v0

    if-eqz v0, :cond_8

    new-instance v0, Landroidx/appcompat/view/menu/e10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    new-instance v0, Landroidx/appcompat/view/menu/k10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/k10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_8
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->a()Z

    move-result v0

    if-eqz v0, :cond_9

    new-instance v0, Landroidx/appcompat/view/menu/o10;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/o10;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_9
    sget-object v0, Landroidx/appcompat/view/menu/l20;->a:Landroidx/appcompat/view/menu/co0;

    if-eqz v0, :cond_a

    new-instance v0, Landroidx/appcompat/view/menu/m20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/m20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_a
    sget-object v0, Landroidx/appcompat/view/menu/n20;->a:Landroidx/appcompat/view/menu/co0;

    if-eqz v0, :cond_b

    new-instance v0, Landroidx/appcompat/view/menu/o20;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/o20;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_b
    sget-object v0, Landroidx/appcompat/view/menu/g30;->a:Landroidx/appcompat/view/menu/co0;

    if-eqz v0, :cond_c

    new-instance v0, Landroidx/appcompat/view/menu/h30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/h30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_c
    sget-object v0, Landroidx/appcompat/view/menu/i30;->a:Landroidx/appcompat/view/menu/co0;

    if-eqz v0, :cond_d

    new-instance v0, Landroidx/appcompat/view/menu/j30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/j30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_d
    sget-object v0, Landroidx/appcompat/view/menu/w30;->a:Landroidx/appcompat/view/menu/co0;

    if-eqz v0, :cond_e

    new-instance v0, Landroidx/appcompat/view/menu/v30;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/v30;-><init>()V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/kz;->a(Landroidx/appcompat/view/menu/l10;)V

    :cond_e
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/kz;->e()V

    sget-object v0, Landroidx/appcompat/view/menu/m8;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0$b;->c(Ljava/lang/Object;)V

    return-void
.end method

.method public e()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/kz;->a:Ljava/util/Map;

    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :catch_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/l10;

    :try_start_0
    invoke-interface {v1}, Landroidx/appcompat/view/menu/l10;->b()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :cond_0
    return-void
.end method
