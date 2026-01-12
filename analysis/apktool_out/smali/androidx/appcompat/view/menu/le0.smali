.class public final Landroidx/appcompat/view/menu/le0;
.super Landroidx/appcompat/view/menu/rg0;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final m:Landroidx/appcompat/view/menu/le0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/le0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/le0;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/le0;->m:Landroidx/appcompat/view/menu/le0;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/rg0;-><init>()V

    return-void
.end method


# virtual methods
.method public bridge synthetic compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 0

    check-cast p1, Ljava/lang/Comparable;

    check-cast p2, Ljava/lang/Comparable;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/le0;->f(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    move-result p1

    return p1
.end method

.method public f(Ljava/lang/Comparable;Ljava/lang/Comparable;)I
    .locals 0

    invoke-static {p1}, Landroidx/appcompat/view/menu/jj0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {p2}, Landroidx/appcompat/view/menu/jj0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-interface {p1, p2}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    move-result p1

    return p1
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    const-string v0, "Ordering.natural()"

    return-object v0
.end method
