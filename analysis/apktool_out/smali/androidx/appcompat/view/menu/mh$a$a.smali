.class public final Landroidx/appcompat/view/menu/mh$a$a;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/jw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/mh$a;-><init>()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# static fields
.field public static final n:Landroidx/appcompat/view/menu/mh$a$a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/mh$a$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/mh$a$a;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/mh$a$a;->n:Landroidx/appcompat/view/menu/mh$a$a;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/mh;
    .locals 1

    instance-of v0, p1, Landroidx/appcompat/view/menu/mh;

    if-eqz v0, :cond_0

    check-cast p1, Landroidx/appcompat/view/menu/mh;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    return-object p1
.end method

.method public bridge synthetic i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/jh$b;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/mh$a$a;->a(Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/mh;

    move-result-object p1

    return-object p1
.end method
