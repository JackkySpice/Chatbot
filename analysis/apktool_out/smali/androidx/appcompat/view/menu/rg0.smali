.class public abstract Landroidx/appcompat/view/menu/rg0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Comparator;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static a(Ljava/util/Comparator;)Landroidx/appcompat/view/menu/rg0;
    .locals 1

    instance-of v0, p0, Landroidx/appcompat/view/menu/rg0;

    if-eqz v0, :cond_0

    check-cast p0, Landroidx/appcompat/view/menu/rg0;

    goto :goto_0

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/hd;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/hd;-><init>(Ljava/util/Comparator;)V

    move-object p0, v0

    :goto_0
    return-object p0
.end method

.method public static c()Landroidx/appcompat/view/menu/rg0;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/le0;->m:Landroidx/appcompat/view/menu/le0;

    return-object v0
.end method


# virtual methods
.method public b(Ljava/lang/Iterable;)Landroidx/appcompat/view/menu/n40;
    .locals 0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/n40;->z(Ljava/util/Comparator;Ljava/lang/Iterable;)Landroidx/appcompat/view/menu/n40;

    move-result-object p1

    return-object p1
.end method

.method public abstract compare(Ljava/lang/Object;Ljava/lang/Object;)I
.end method

.method public d()Landroidx/appcompat/view/menu/rg0;
    .locals 1

    invoke-static {}, Landroidx/appcompat/view/menu/va0;->b()Landroidx/appcompat/view/menu/tw;

    move-result-object v0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/rg0;->e(Landroidx/appcompat/view/menu/tw;)Landroidx/appcompat/view/menu/rg0;

    move-result-object v0

    return-object v0
.end method

.method public e(Landroidx/appcompat/view/menu/tw;)Landroidx/appcompat/view/menu/rg0;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/e9;

    invoke-direct {v0, p1, p0}, Landroidx/appcompat/view/menu/e9;-><init>(Landroidx/appcompat/view/menu/tw;Landroidx/appcompat/view/menu/rg0;)V

    return-object v0
.end method
