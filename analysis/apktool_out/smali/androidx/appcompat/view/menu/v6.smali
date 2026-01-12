.class public Landroidx/appcompat/view/menu/v6;
.super Landroidx/appcompat/view/menu/n00$a;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/k30;


# static fields
.field public static final l:Landroidx/appcompat/view/menu/v6;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/v6;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/v6;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/v6;->l:Landroidx/appcompat/view/menu/v6;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/n00$a;-><init>()V

    return-void
.end method

.method public static h()Landroidx/appcompat/view/menu/v6;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/v6;->l:Landroidx/appcompat/view/menu/v6;

    return-object v0
.end method


# virtual methods
.method public P(Landroidx/appcompat/view/menu/x6;I)I
    .locals 3

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    new-instance v1, Landroidx/appcompat/view/menu/oo0;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/oo0;-><init>()V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    new-instance v1, Landroidx/appcompat/view/menu/bi;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/bi;-><init>()V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v1, p1, Landroidx/appcompat/view/menu/x6;->o:Landroidx/appcompat/view/menu/l50;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/sp;

    invoke-interface {v2, p1, v1, p2}, Landroidx/appcompat/view/menu/sp;->a(Landroidx/appcompat/view/menu/x6;Landroidx/appcompat/view/menu/l50;I)I

    move-result v2

    if-eqz v2, :cond_0

    return v2

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public b1(Landroidx/appcompat/view/menu/x6;ZI)I
    .locals 2

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    if-eqz p2, :cond_0

    new-instance p2, Landroidx/appcompat/view/menu/no0;

    invoke-direct {p2}, Landroidx/appcompat/view/menu/no0;-><init>()V

    invoke-interface {v0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_0
    new-instance p2, Landroidx/appcompat/view/menu/oo0;

    invoke-direct {p2}, Landroidx/appcompat/view/menu/oo0;-><init>()V

    invoke-interface {v0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object p2, p1, Landroidx/appcompat/view/menu/x6;->o:Landroidx/appcompat/view/menu/l50;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/sp;

    invoke-interface {v1, p1, p2, p3}, Landroidx/appcompat/view/menu/sp;->a(Landroidx/appcompat/view/menu/x6;Landroidx/appcompat/view/menu/l50;I)I

    move-result v1

    if-eqz v1, :cond_1

    return v1

    :cond_2
    const/4 p1, 0x0

    return p1
.end method

.method public j()V
    .locals 0

    return-void
.end method

.method public j1(Landroidx/appcompat/view/menu/x6;)I
    .locals 4

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    new-instance v1, Landroidx/appcompat/view/menu/ai;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/ai;-><init>()V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    new-instance v1, Landroidx/appcompat/view/menu/dh;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/dh;-><init>()V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v1, p1, Landroidx/appcompat/view/menu/x6;->o:Landroidx/appcompat/view/menu/l50;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/sp;

    const/4 v3, -0x1

    invoke-interface {v2, p1, v1, v3}, Landroidx/appcompat/view/menu/sp;->a(Landroidx/appcompat/view/menu/x6;Landroidx/appcompat/view/menu/l50;I)I

    move-result v2

    if-eqz v2, :cond_0

    return v2

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public w(Landroidx/appcompat/view/menu/x6;I)I
    .locals 3

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    new-instance v1, Landroidx/appcompat/view/menu/bi;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/bi;-><init>()V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    new-instance v1, Landroidx/appcompat/view/menu/ai;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/ai;-><init>()V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    new-instance v1, Landroidx/appcompat/view/menu/dh;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/dh;-><init>()V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v1, p1, Landroidx/appcompat/view/menu/x6;->o:Landroidx/appcompat/view/menu/l50;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/sp;

    invoke-interface {v2, p1, v1, p2}, Landroidx/appcompat/view/menu/sp;->a(Landroidx/appcompat/view/menu/x6;Landroidx/appcompat/view/menu/l50;I)I

    move-result v2

    if-eqz v2, :cond_0

    return v2

    :cond_1
    const/4 p1, 0x0

    return p1
.end method
