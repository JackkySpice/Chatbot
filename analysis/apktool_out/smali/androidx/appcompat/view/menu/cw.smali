.class public final Landroidx/appcompat/view/menu/cw;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/cw;

.field public static final b:Landroidx/appcompat/view/menu/ew;

.field public static final c:Landroidx/appcompat/view/menu/ew;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/cw;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/cw;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/cw;->a:Landroidx/appcompat/view/menu/cw;

    new-instance v1, Landroidx/appcompat/view/menu/dw;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/dw;-><init>()V

    sput-object v1, Landroidx/appcompat/view/menu/cw;->b:Landroidx/appcompat/view/menu/ew;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/cw;->b()Landroidx/appcompat/view/menu/ew;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/cw;->c:Landroidx/appcompat/view/menu/ew;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final a(Landroidx/appcompat/view/menu/ev;Landroidx/appcompat/view/menu/ev;ZLandroidx/appcompat/view/menu/n4;Z)V
    .locals 0

    const-string p4, "inFragment"

    invoke-static {p0, p4}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p4, "outFragment"

    invoke-static {p1, p4}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p4, "sharedElements"

    invoke-static {p3, p4}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ev;->t()Landroidx/appcompat/view/menu/st0;

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ev;->t()Landroidx/appcompat/view/menu/st0;

    :goto_0
    return-void
.end method

.method public static final c(Landroidx/appcompat/view/menu/n4;Landroidx/appcompat/view/menu/n4;)V
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "namedViews"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ju0;->size()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    :goto_0
    const/4 v1, -0x1

    if-ge v1, v0, :cond_1

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/ju0;->m(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {p1, v1}, Landroidx/appcompat/view/menu/ju0;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/ju0;->k(I)Ljava/lang/Object;

    :cond_0
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public static final d(Ljava/util/List;I)V
    .locals 1

    const-string v0, "views"

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Ljava/lang/Iterable;

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    invoke-virtual {v0, p1}, Landroid/view/View;->setVisibility(I)V

    goto :goto_0

    :cond_0
    return-void
.end method


# virtual methods
.method public final b()Landroidx/appcompat/view/menu/ew;
    .locals 3

    :try_start_0
    const-class v0, Landroidx/appcompat/view/menu/fw;

    const-string v1, "null cannot be cast to non-null type java.lang.Class<androidx.fragment.app.FragmentTransitionImpl>"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Class;

    invoke-virtual {v0, v2}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    move-result-object v0

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {v0, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/ew;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method
