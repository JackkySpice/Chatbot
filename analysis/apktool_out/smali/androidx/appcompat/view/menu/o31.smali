.class public final Landroidx/appcompat/view/menu/o31;
.super Landroidx/appcompat/view/menu/mh;
.source "SourceFile"


# static fields
.field public static final o:Landroidx/appcompat/view/menu/o31;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/o31;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/o31;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/o31;->o:Landroidx/appcompat/view/menu/o31;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/mh;-><init>()V

    return-void
.end method


# virtual methods
.method public A(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V
    .locals 2

    sget-object p1, Landroidx/appcompat/view/menu/wj;->u:Landroidx/appcompat/view/menu/wj;

    sget-object v0, Landroidx/appcompat/view/menu/gz0;->h:Landroidx/appcompat/view/menu/yy0;

    const/4 v1, 0x0

    invoke-virtual {p1, p2, v0, v1}, Landroidx/appcompat/view/menu/rr0;->G(Ljava/lang/Runnable;Landroidx/appcompat/view/menu/yy0;Z)V

    return-void
.end method

.method public E(I)Landroidx/appcompat/view/menu/mh;
    .locals 1

    invoke-static {p1}, Landroidx/appcompat/view/menu/b90;->a(I)V

    sget v0, Landroidx/appcompat/view/menu/gz0;->d:I

    if-lt p1, v0, :cond_0

    return-object p0

    :cond_0
    invoke-super {p0, p1}, Landroidx/appcompat/view/menu/mh;->E(I)Landroidx/appcompat/view/menu/mh;

    move-result-object p1

    return-object p1
.end method
